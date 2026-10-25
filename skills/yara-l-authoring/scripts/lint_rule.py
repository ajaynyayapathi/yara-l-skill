#!/usr/bin/env python3
"""Offline structural lint for YARA-L 2.0 rules.

Catches common authoring mistakes before you paste a rule into the
Google SecOps Rules Editor. It does NOT replace the SecOps compiler:
a clean lint result does not mean the rule compiles.

Usage:
    python3 lint_rule.py rule.yaral [more.yaral ...]

Exit code is 1 if any file has errors, 0 otherwise.
"""

import re
import sys

SECTION_ORDER = ["meta", "events", "match", "outcome", "condition", "options"]
REQUIRED_SECTIONS = {"meta", "events", "condition"}
REQUIRED_META = [
    "author", "description", "severity", "priority",
    "mitre_attack_tactic", "mitre_attack_technique",
    "reference", "rule_version", "false_positives", "yara_version",
]
VALID_EVENT_TYPES = {
    "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_DELETION",
    "USER_CHANGE_PERMISSIONS", "USER_CHANGE_PASSWORD", "USER_RESOURCE_ACCESS",
    "USER_RESOURCE_CREATION", "USER_RESOURCE_DELETION",
    "USER_RESOURCE_UPDATE_CONTENT", "USER_RESOURCE_UPDATE_PERMISSIONS",
    "USER_UNCATEGORIZED", "USER_STATS", "USER_COMMUNICATION",
    "GROUP_CREATION", "GROUP_DELETION", "GROUP_MODIFICATION",
    "PROCESS_LAUNCH", "PROCESS_TERMINATION", "PROCESS_INJECTION",
    "PROCESS_OPEN", "PROCESS_MODULE_LOAD", "PROCESS_PRIVILEGE_ESCALATION",
    "PROCESS_UNCATEGORIZED",
    "FILE_CREATION", "FILE_MODIFICATION", "FILE_DELETION", "FILE_READ",
    "FILE_COPY", "FILE_MOVE", "FILE_OPEN", "FILE_SYNC", "FILE_UNCATEGORIZED",
    "NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "NETWORK_DHCP",
    "NETWORK_FLOW", "NETWORK_FTP", "NETWORK_SMTP", "NETWORK_UNCATEGORIZED",
    "REGISTRY_CREATION", "REGISTRY_MODIFICATION", "REGISTRY_DELETION",
    "REGISTRY_UNCATEGORIZED",
    "SERVICE_CREATION", "SERVICE_DELETION", "SERVICE_MODIFICATION",
    "SERVICE_START", "SERVICE_STOP", "SERVICE_UNSPECIFIED",
    "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION",
    "SCHEDULED_TASK_ENABLE", "SCHEDULED_TASK_DISABLE",
    "SCHEDULED_TASK_MODIFICATION", "SCHEDULED_TASK_UNCATEGORIZED",
    "EMAIL_TRANSACTION", "EMAIL_UNCATEGORIZED", "EMAIL_URL_CLICK",
    "STATUS_UPDATE", "STATUS_HEARTBEAT", "STATUS_STARTUP", "STATUS_SHUTDOWN",
    "STATUS_UNCATEGORIZED",
    "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_READ",
    "RESOURCE_WRITTEN", "RESOURCE_PERMISSIONS_CHANGE",
    "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION",
    "SETTING_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_UNCATEGORIZED",
    "SYSTEM_AUDIT_LOG_WIPE", "DEVICE_CONFIG_UPDATE", "DEVICE_FIRMWARE_UPDATE",
    "DEVICE_PROGRAM_UPLOAD", "DEVICE_PROGRAM_DOWNLOAD",
    "ANALYST_ADD_COMMENT", "ANALYST_UPDATE_PRIORITY", "ANALYST_UPDATE_REASON",
    "ANALYST_UPDATE_REPUTATION", "ANALYST_UPDATE_RISK_SCORE",
    "ANALYST_UPDATE_ROOT_CAUSE", "ANALYST_UPDATE_SEVERITY_SCORE",
    "ANALYST_UPDATE_STATUS", "ANALYST_UPDATE_VERDICT",
    "GENERIC_EVENT", "EVENTTYPE_UNSPECIFIED",
}
INT_FIELDS = (".port", "sent_bytes", "received_bytes", ".pid")
AGGREGATES = ("count(", "count_distinct(", "sum(", "min(", "max(",
              "array(", "array_distinct(", "avg(", "stddev(")


def strip_comments(text):
    """Remove // comments while leaving string and regex literals intact."""
    out = []
    for line in text.splitlines():
        in_quote = None
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if in_quote:
                if ch == "\\" and in_quote == '"':
                    i += 2
                    continue
                if ch == in_quote:
                    in_quote = None
            elif ch in ('"', "`"):
                in_quote = ch
            elif line.startswith("//", i):
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def split_sections(body):
    """Return list of (section_name, content) in source order."""
    pattern = re.compile(r"^\s*(" + "|".join(SECTION_ORDER) + r")\s*:", re.M)
    hits = list(pattern.finditer(body))
    sections = []
    for i, m in enumerate(hits):
        end = hits[i + 1].start() if i + 1 < len(hits) else len(body)
        sections.append((m.group(1), body[m.end():end]))
    return sections


def lint(path):
    errors, warnings = [], []
    raw = open(path, encoding="utf-8").read()
    text = strip_comments(raw)

    m = re.search(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", text)
    if not m:
        return ["no 'rule <name> {' header found"], warnings
    name = m.group(1)
    if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        warnings.append(f"rule name '{name}' is not lowercase snake_case")

    if text.count("{") != text.count("}"):
        errors.append("unbalanced braces")

    body = text[m.end():text.rfind("}")]
    sections = split_sections(body)
    names = [s for s, _ in sections]
    content = {s: c for s, c in sections}

    for req in REQUIRED_SECTIONS - set(names):
        errors.append(f"missing required section '{req}'")
    if len(names) != len(set(names)):
        errors.append("a section appears more than once")
    order = [SECTION_ORDER.index(s) for s in names]
    if order != sorted(order):
        errors.append(f"sections out of order: {names}; expected order {SECTION_ORDER}")

    meta = content.get("meta", "")
    for key in REQUIRED_META:
        if not re.search(rf"^\s*{key}\s*=", meta, re.M):
            warnings.append(f"meta missing '{key}'")

    events = content.get("events", "")
    variables = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\.", events))
    for var in sorted(variables):
        if not re.search(rf"\${var}\.metadata\.event_type\s*=", events):
            warnings.append(f"event variable ${var} has no metadata.event_type filter")

    for et in re.findall(r"metadata\.event_type\s*=\s*\"([^\"]+)\"", events):
        if et not in VALID_EVENT_TYPES:
            errors.append(f"unknown metadata.event_type value \"{et}\"")

    for field in INT_FIELDS:
        if re.search(re.escape(field) + r"\s*(=|!=|<|>)\s*\"", events):
            errors.append(f"integer field ending '{field}' compared to a quoted string")

    for pat in re.findall(r"re\.regex\([^,]+,\s*[`\"](.*?)[`\"]\s*\)", events):
        if pat.startswith(".*") or pat.startswith("(?i).*"):
            warnings.append(f"regex starts with .* (slow): {pat}")

    has_match = "match" in content
    if len(variables) > 1 and not has_match:
        errors.append("multiple event variables but no match section")

    if has_match:
        match_vars = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", content["match"]))
        if not re.search(r"\bover\s+\d+\s*[mhd]\b", content["match"]):
            errors.append("match section has no 'over <N>[m|h|d]' window")
        for var in sorted(variables):
            joined = any(re.search(rf"\${var}\.[\w.\[\]\"]+\s*=\s*\${mv}\b", events)
                         or re.search(rf"\${mv}\s*=\s*\${var}\.", events)
                         for mv in match_vars)
            if not joined:
                warnings.append(f"${var} is not assigned to any match placeholder")

    outcome = content.get("outcome", "")
    out_vars = re.findall(r"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=", outcome, re.M)
    if len(out_vars) > 20:
        errors.append(f"{len(out_vars)} outcome variables; limit is 20")
    if "risk_score" not in out_vars:
        warnings.append("no $risk_score in outcome")
    if has_match:
        for line in outcome.splitlines():
            lm = re.match(r"\s*\$(\w+)\s*=\s*(.+)", line)
            if not lm:
                continue
            expr = lm.group(2)
            refs_event = any(re.search(rf"\${v}\.", expr) for v in variables)
            if refs_event and not any(a in expr for a in AGGREGATES):
                errors.append(f"outcome ${lm.group(1)} uses an event field without an aggregate")

    cond = content.get("condition", "")
    if re.search(r"!\s*\$", cond) and not has_match:
        errors.append("absence condition (!$var) requires a match section")

    if "VERIFY" in raw:
        n = raw.count("VERIFY")
        warnings.append(f"{n} field(s) marked VERIFY; confirm against a real event")

    for ref in sorted(set(re.findall(r"%([A-Za-z_][A-Za-z0-9_]*)", text))):
        warnings.append(f"depends on reference list or data table '%{ref}'")

    return errors, warnings


def main(paths):
    if not paths:
        print(__doc__)
        return 2
    failed = False
    for p in paths:
        errors, warnings = lint(p)
        status = "FAIL" if errors else "OK"
        print(f"[{status}] {p}")
        for e in errors:
            print(f"  error:   {e}")
        for w in warnings:
            print(f"  warning: {w}")
        failed |= bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
