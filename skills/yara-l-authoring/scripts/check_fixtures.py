#!/usr/bin/env python3
"""Check YARA-L rules against parser fixtures.

A fixture is a sanitized sample event, as one specific parser normalized it
to UDM, paired with the rule it should (or should not) trigger. This script
answers a different question than lint_rule.py:

    lint_rule.py       Is the rule written correctly?
    check_fixtures.py  Does the rule line up with what this parser emits?

For every fixture it:

1. Validates the fixture file layout.
2. Scans raw logs and UDM events for unsanitized data (public IPs, real
   email domains, tenant or object GUIDs).
3. Confirms every UDM field the rule references exists in the fixture's
   events, so a rule can't depend on a field the parser never fills.
4. Evaluates simple conditions (string and integer equality, re.regex, and
   #var thresholds) and reports when the result disagrees with "expect".

It is NOT a rule engine. It ignores match windows, timestamp ordering,
reference lists, data tables, functions other than re.regex, and outcome
logic. A pass here means the fields and literal values line up, nothing more.

Usage:
    python3 check_fixtures.py                 # all fixtures under ../fixtures
    python3 check_fixtures.py path/to/fixture.json [...]

Exit code is 1 if any fixture has errors, 0 otherwise.
"""

import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
FIXTURE_DIR = os.path.join(SKILL_DIR, "fixtures")
RULE_DIRS = [os.path.join(SKILL_DIR, "examples"), os.path.join(SKILL_DIR, "rules")]

sys.path.insert(0, HERE)
from lint_rule import split_sections, strip_comments  # noqa: E402

REQUIRED_KEYS = {"description", "log_type", "parser", "rule", "expect",
                 "verified_against_tenant", "raw_logs", "udm_events"}

DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
SAFE_EMAIL_DOMAINS = re.compile(r"@([\w-]+\.)*(example\.(com|net|org)|[\w-]+\.example)$", re.I)
PLACEHOLDER_GUID = re.compile(r"^0{8}-0{4}-0{4}-0{4}-0{8}[0-9a-f]{4}$", re.I)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
GUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


# ---------------------------------------------------------------- helpers

def snake(name):
    """Convert camelCase keys from SecOps API exports to YARA-L snake_case."""
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()


# Map typed UDM fields. Their keys are data (accessed as field["key"]), not
# schema names, so they keep their original spelling.
MAP_FIELDS = {"fields", "labels", "detection_fields", "rule_labels", "outcomes"}


def normalize(obj, keep_keys=False):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = k if keep_keys else snake(k)
            out[nk] = normalize(v, keep_keys=nk in MAP_FIELDS and isinstance(v, dict))
        return out
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    return obj


def walk_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)
    elif isinstance(obj, str):
        yield obj


PATH_TOKEN = re.compile(r'([A-Za-z_]\w*)(?:\["([^"]+)"\])?')


def resolve(event, path):
    """Return every leaf value at a dotted UDM path. Lists fan out."""
    nodes = [event]
    for name, key in PATH_TOKEN.findall(path):
        nxt = []
        for node in nodes:
            items = node if isinstance(node, list) else [node]
            for item in items:
                if isinstance(item, str) and name in ("seconds", "nanos"):
                    nxt.append(item)  # RFC 3339 timestamp string stands in for .seconds
                    continue
                if not isinstance(item, dict) or name not in item:
                    continue
                val = item[name]
                if key:
                    val = lookup_key(val, key)
                    if val is None:
                        continue
                nxt.append(val)
        nodes = nxt
    leaves = []
    for n in nodes:
        leaves.extend(n if isinstance(n, list) else [n])
    return leaves


def lookup_key(container, key):
    """Support map style {"k": v} and list style [{"key": k, "value": v}]."""
    if isinstance(container, dict):
        val = container.get(key)
    elif isinstance(container, list):
        val = next((e.get("value") for e in container
                    if isinstance(e, dict) and e.get("key") == key), None)
    else:
        return None
    if isinstance(val, dict) and len(val) == 1:
        (only,) = val.values()  # unwrap {"string_value": "x"}
        return only
    return val


# ---------------------------------------------------------------- rule parsing

FIELD = r"\$(\w+)\.([\w.]+(?:\[\"[^\"]+\"\])?(?:\.[\w.]+)?)"
EQ_STR = re.compile(rf"^{FIELD}\s*(=|!=)\s*\"((?:[^\"\\]|\\.)*)\"\s*(nocase)?$")
EQ_INT = re.compile(rf"^{FIELD}\s*(=|!=|>=|<=|>|<)\s*(-?\d+)$")
REGEX = re.compile(rf"^re\.regex\(\s*{FIELD}\s*,\s*`([^`]*)`\s*\)\s*(nocase)?$")
ANY_FIELD = re.compile(FIELD)
THRESHOLD = re.compile(r"#(\w+)\s*(>=|>|=|==)\s*(\d+)")


def find_rule(name):
    for d in RULE_DIRS:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".yaral"):
                continue
            path = os.path.join(d, fn)
            text = open(path, encoding="utf-8").read()
            if re.search(rf"\brule\s+{re.escape(name)}\s*\{{", text):
                return path, text
    return None, None


def parse_rule(text):
    clean = strip_comments(text)
    m = re.search(r"\brule\s+\w+\s*\{", clean)
    body = clean[m.end():clean.rfind("}")]
    sections = dict(split_sections(body))
    checks, required = [], set()
    for raw in sections.get("events", "").splitlines():
        line = raw.strip()
        if not line:
            continue
        negated = line.startswith("not ")
        for var, path in ANY_FIELD.findall(line):
            required.add((var, path))
        if negated:
            continue  # exclusions usually hit lists or tables; skip evaluation
        if (mm := EQ_STR.match(line)):
            var, path, op, lit, nocase = mm.groups()
            checks.append(("str", var, path, op, lit.replace('\\\\', '\\'), bool(nocase)))
        elif (mm := EQ_INT.match(line)):
            var, path, op, num = mm.groups()
            checks.append(("int", var, path, op, int(num), False))
        elif (mm := REGEX.match(line)):
            var, path, pat, nocase = mm.groups()
            checks.append(("re", var, path, "~", pat, bool(nocase)))
    cond = sections.get("condition", "")
    thresholds = {v: (op, int(n)) for v, op, n in THRESHOLD.findall(cond)}
    absent = set(re.findall(r"!\s*\$(\w+)", cond))
    variables = {v for v, _ in required}
    return checks, required, thresholds, variables, absent


def check_passes(check, event):
    kind, _, path, op, want, nocase = check
    values = resolve(event, path)
    if kind == "str":
        hit = any(isinstance(v, str) and
                  ((v.lower() == want.lower()) if nocase else (v == want))
                  for v in values)
        return hit if op == "=" else (bool(values) and not hit)
    if kind == "int":
        nums = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
        ops = {"=": lambda a: a == want, "!=": lambda a: a != want, ">": lambda a: a > want,
               "<": lambda a: a < want, ">=": lambda a: a >= want, "<=": lambda a: a <= want}
        return any(ops[op](n) for n in nums)
    flags = re.I if nocase else 0
    try:
        rx = re.compile(want, flags)
    except re.error:
        return None  # RE2 syntax Python can't compile; skip
    return any(isinstance(v, str) and rx.search(v) for v in values)


# ---------------------------------------------------------------- fixture check

def sanitization_issues(fixture):
    errors, warnings = [], []
    blob = list(walk_strings(fixture["raw_logs"])) + list(walk_strings(fixture["udm_events"]))
    for s in blob:
        for ip in IP_RE.findall(s):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in DOC_NETS):
                continue
            if any(addr in n for n in PRIVATE_NETS):
                warnings.append(f"private IP {ip}; prefer 192.0.2.x, 198.51.100.x, 203.0.113.x")
            else:
                errors.append(f"public IP {ip}; replace with a documentation range (RFC 5737)")
        for email in EMAIL_RE.findall(s):
            if not SAFE_EMAIL_DOMAINS.search(email):
                errors.append(f"email {email}; use a domain under example.com")
        for guid in GUID_RE.findall(s):
            if not PLACEHOLDER_GUID.match(guid):
                errors.append(f"GUID {guid}; replace with 00000000-0000-0000-0000-00000000000N")
    return sorted(set(errors)), sorted(set(warnings))


def check_fixture(path):
    errors, warnings, notes = [], [], []
    try:
        fixture = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read fixture: {exc}"], [], []

    missing = REQUIRED_KEYS - fixture.keys()
    if missing:
        return [f"missing keys: {sorted(missing)}"], [], []
    if fixture["expect"] not in ("fire", "no_fire"):
        errors.append('expect must be "fire" or "no_fire"')
    if not fixture["udm_events"]:
        errors.append("udm_events is empty")
    folder = os.path.basename(os.path.dirname(path))
    if folder != fixture["log_type"]:
        warnings.append(f"fixture sits in {folder}/ but log_type is {fixture['log_type']}")
    if not fixture["verified_against_tenant"]:
        notes.append("synthetic: field names and values not yet confirmed against a live tenant")

    e, w = sanitization_issues(fixture)
    errors += e
    warnings += w

    rule_path, rule_text = find_rule(fixture["rule"])
    if not rule_path:
        errors.append(f"rule '{fixture['rule']}' not found in examples/ or rules/")
        return errors, warnings, notes

    events = [normalize(ev) for ev in fixture["udm_events"]]
    checks, required, thresholds, variables, absent = parse_rule(rule_text)

    # 1. Field presence: every referenced field must exist in at least one event.
    #    Fields on an absence variable (!$var) are exempt: those events are
    #    supposed to be missing from a fire fixture.
    for var, field in sorted(required):
        if var in absent:
            continue
        if not any(resolve(ev, field) for ev in events):
            msg = f"${var}.{field} is referenced by the rule but absent from every fixture event"
            (errors if fixture["expect"] == "fire" else warnings).append(msg)

    # 2. Evaluate positive conditions per event variable.
    by_var = {v: [c for c in checks if c[1] == v] for v in variables}
    matched_counts = {}
    for var, var_checks in by_var.items():
        count = 0
        for ev in events:
            results = [check_passes(c, ev) for c in var_checks]
            if all(r is not False for r in results):
                count += 1
        matched_counts[var] = count

    def satisfied(var):
        n = matched_counts.get(var, 0)
        if var in absent:
            return n == 0
        if var in thresholds:
            op, want = thresholds[var]
            return {">=": n >= want, ">": n > want, "=": n == want, "==": n == want}[op]
        return n >= 1

    all_satisfied = all(satisfied(v) for v in variables)

    if fixture["expect"] == "fire" and not all_satisfied:
        for var in sorted(variables):
            if satisfied(var):
                continue
            if var in absent:
                errors.append(f"${var}: {matched_counts[var]} event(s) match, but the condition "
                              f"requires !${var} (none)")
                continue
            errors.append(f"${var}: {matched_counts.get(var, 0)} event(s) match its conditions"
                          + (f", rule needs #{var} {thresholds[var][0]} {thresholds[var][1]}"
                             if var in thresholds else ", rule needs at least 1"))
            for c in by_var[var]:
                if not any(check_passes(c, ev) is not False for ev in events):
                    seen = sorted({str(v) for ev in events for v in resolve(ev, c[2])})[:5]
                    errors.append(f"  {c[2]}: rule wants {c[3]} {c[4]!r}, fixture has {seen or 'nothing'}")
    elif fixture["expect"] == "no_fire" and all_satisfied:
        if fixture.get("relies_on_exclusion"):
            notes.append(f"positive conditions match; suppression relies on {fixture['relies_on_exclusion']}")
        else:
            errors.append("expect is no_fire but every evaluated condition matches; "
                          "set relies_on_exclusion if a list, table, or window suppresses it")

    return errors, warnings, notes


def collect(paths):
    if paths:
        return paths
    found = []
    for root, _, files in os.walk(FIXTURE_DIR):
        found += [os.path.join(root, f) for f in sorted(files)
                  if f.endswith(".json") and not f.startswith("_")]
    return sorted(found)


def main(argv):
    paths = collect(argv)
    if not paths:
        print("no fixtures found")
        return 0
    failed = False
    for p in paths:
        errors, warnings, notes = check_fixture(p)
        rel = os.path.relpath(p, SKILL_DIR)
        print(f"[{'FAIL' if errors else 'OK'}] {rel}")
        for e in errors:
            print(f"  error:   {e}")
        for w in warnings:
            print(f"  warning: {w}")
        for n in notes:
            print(f"  note:    {n}")
        failed |= bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
