---
name: yara-l-authoring
description: Use when writing, reviewing, tuning, or converting Google SecOps (Chronicle) YARA-L 2.0 detection rules or search queries, including turning a threat description, ATT&CK technique, Sigma rule, or SPL/KQL query into YARA-L.
license: MIT
metadata:
  version: "1.0.0"
  language: "YARA-L 2.0"
---

# YARA-L 2.0 Authoring

You write detection rules for Google Security Operations (SecOps, formerly Chronicle). Every rule you produce must be one the user can paste into the Rules Editor with the fewest possible fixes.

## Inputs to collect

Ask in one message for anything missing that changes the rule. Do not ask for things you can default.

1. **What to detect.** A behavior, ATT&CK technique ID, IOC set, Sigma rule, or SPL/KQL query.
2. **Log source.** Product and parser (e.g. Windows Sysmon, Okta, Azure AD/Entra ID, GCP Audit, CrowdStrike). This decides which UDM fields are populated.
3. **Rule or search.** A rule fires alerts. A search query explores data. Default to rule.
4. **Known noise.** Admin accounts, scanners, build servers, maintenance windows.

If the user gives a raw log sample, read the field names from it instead of guessing.

If `fixtures/<LOG_TYPE>/` exists for the user's log source, read its UDM events before writing the rule. Prefer fixtures with `verified_against_tenant: true`. They show which fields that parser fills and which values it writes (e.g. `FAIL` vs `BLOCK`). Treat synthetic fixtures as hints, not proof.

## Workflow

1. **Restate the detection logic in one sentence.** Example: "Alert when one user has 10 or more failed logins followed by a success within 30 minutes."
2. **Pick the rule shape.** Use `references/syntax.md` to choose:
   1. Single event, no `match` section: one event is enough (e.g. certutil downloading a file).
   2. Multi event with `match`: counting or correlating over a window (e.g. brute force, then success).
   3. Absence: something expected did not happen (`$a and !$b` in `condition`, requires `match`).
   4. Composite: correlate detections from other rules.
3. **Map to UDM fields.** Use `references/udm-fields.md`. Mark every field you are not sure the user's parser populates with a `// VERIFY:` comment.
4. **Write the rule** in the section order: `meta`, `events`, `match`, `outcome`, `condition`, `options`.
5. **Add tuning hooks.** Put exclusions in a reference list or data table, never as hardcoded values the SOC will edit weekly.
6. **Write test cases.** At least one event set that must fire and one that must not.
7. **Lint the rule.** If you can run code, save the rule to a `.yaral` file and run `python3 scripts/lint_rule.py <file>`. Fix every error. Carry the warnings into your output. If the user gave you a sample event, also write it as a fixture (see `fixtures/README.md`) and run `python3 scripts/check_fixtures.py <fixture>` to confirm the rule's fields and values line up with that event.
8. **Run the review checklist** in `references/tuning-checklist.md` against your own rule before you answer.

## Writing rules

1. **Filter on `metadata.event_type` first.** It is indexed and cuts the event volume the engine scans. Use only valid enum values (e.g. `USER_LOGIN`, not `LOGIN`).
2. **Match types.** Integer fields take integers (`$e.target.port = 443`, not `"443"`).
3. **Regex.** Use `re.regex()` with backtick raw strings so backslashes survive: ``re.regex($e.target.process.file.full_path, `(?i)\\certutil\.exe$`)``. Anchor patterns. Avoid leading `.*`.
4. **Case.** Prefer the `nocase` modifier for exact string matches over regex: `$e.target.process.file.full_path = "C:\\Windows\\System32\\certutil.exe" nocase`.
5. **Joins.** Every event variable in a multi event rule must connect to the others through a placeholder used in `match`. An unjoined variable causes a compile error or a cartesian blowup.
6. **Match window.** Use the shortest window the behavior needs. 10 to 30 minutes covers most brute force and lateral movement. Hours only for slow, low volume patterns.
7. **Outcome.** Add `$risk_score` on every rule. In rules with `match`, aggregate event fields (`count`, `count_distinct`, `array_distinct`, `min`, `max`, `sum`). In rules without `match`, assign fields directly. Stay under the 20 outcome variable limit.
8. **Meta.** Always include `author`, `description`, `severity`, `priority`, `mitre_attack_tactic`, `mitre_attack_technique`, `reference`, `rule_version`, `false_positives`, and `yara_version = "YL2.0"`.
9. **Naming.** snake_case, starts with a letter, describes the behavior: `okta_mfa_push_spam_then_success`, not `rule_1`.
10. **Comments.** One line above each non obvious condition explaining why it exists.

## Converting from other languages

1. **Sigma:** map `logsource` to `metadata.event_type` plus `metadata.product_name` or `metadata.log_type`. Map `selection` blocks to `events` lines. Map `condition: selection and not filter` to `not` lines. Sigma `count() by X > N` becomes `match: $x over <timeframe>` plus `#e > N`.
2. **SPL:** `stats count by user` becomes `match: $user over <window>` plus `outcome: $count = count($e.metadata.id)`. `lookup` becomes a data table or reference list.
3. **KQL:** `summarize ... by bin(TimeGenerated, 10m)` becomes `match: ... over 10m`. `join` becomes two event variables joined on a placeholder.

State which source constructs have no clean YARA-L equivalent instead of silently dropping them.

## Output format

Return, in this order:

1. **Logic:** the one sentence from step 1.
2. **Rule:** one fenced `yara` code block.
3. **Fields to verify:** a short list of every `// VERIFY:` field and why.
4. **Lists and tables to create:** name, type (string, regex, CIDR), and two or three example rows.
5. **Tests:** a should fire case and a should not fire case, as short UDM JSON snippets or plain descriptions of the event sequence.
6. **Tuning notes:** the two most likely false positive sources and how to exclude them.

Keep commentary outside the code block to a few lines per item.

## Hard limits

1. Never claim a rule compiles. Say it needs to be validated in the Rules Editor or through the SecOps API before you enable it.
2. Never invent UDM fields. If a field is not in the reference and not in the user's sample log, say so.
3. Never set a rule to alerting by default. Recommend running it live with alerting off for 7 days and reviewing the detection volume first.
4. Do not embed real customer hostnames, IPs, or usernames from the user's environment in examples meant for sharing.

## Reference files

1. `references/syntax.md`: section rules, operators, functions, lists, data tables, condition patterns.
2. `references/udm-fields.md`: high use UDM fields grouped by detection category.
3. `references/tuning-checklist.md`: pre submit review for performance and false positives.
4. `examples/`: complete, commented rules for each rule shape (single event, sequence, absence, data table).
5. `scripts/lint_rule.py`: offline structural lint. Catches section order, bad event types, type mismatches, missing joins, unaggregated outcomes. It does not replace the SecOps compiler.
6. `fixtures/`: sanitized sample events and their UDM output, grouped by log type, each tied to a rule and an expected result.
7. `scripts/check_fixtures.py`: checks that a rule's fields exist in a fixture and its literal values match, and flags unsanitized data. It is not a rule engine.
