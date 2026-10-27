# YARA-L Authoring Skill

An [Agent Skill](https://agentskills.io) that teaches AI coding agents to write, review, tune, and convert **YARA-L 2.0** detection rules for Google Security Operations (SecOps, formerly Chronicle).

Works with Claude Code, Claude.ai, GitHub Copilot, OpenAI Codex, Gemini CLI, Cursor, and any client that reads the `SKILL.md` format.

## What it does

Give your agent a threat description, an ATT&CK technique, a Sigma rule, or an SPL/KQL query. It returns:

1. A one sentence statement of the detection logic
2. A complete YARA-L 2.0 rule with full meta, outcome, and `$risk_score`
3. A list of UDM fields to verify against your parser
4. The reference lists and data tables to create, with sample rows
5. A should fire test and a should not fire test
6. The two most likely false positive sources and how to tune them out

It also ships an offline linter that catches the mistakes the Rules Editor would reject.

## Example prompts

```
Write a YARA-L rule for 10 failed logins followed by a success within 30 minutes.
Convert this Sigma rule to YARA-L: <paste>
Review this YARA-L rule for performance and false positives: <paste>
Detect OAuth device code sign ins from Entra ID for users outside an approved list.
```

## Install

Copy the `skills/yara-l-authoring` folder to your agent's skill directory.

| Agent | Personal | Project |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| GitHub Copilot / VS Code | `~/.copilot/skills/` | `.github/skills/` |
| Codex and other clients | `~/.agents/skills/` | `.agents/skills/` |

```bash
git clone https://github.com/ajaynyayapathi/yara-l-skill.git
cp -r yara-l-skill/skills/yara-l-authoring ~/.claude/skills/
```

For Claude.ai, zip the `yara-l-authoring` folder and upload it as a custom skill.

## Repository layout

```
skills/yara-l-authoring/
  SKILL.md                     Instructions the agent loads
  references/
    syntax.md                  Sections, operators, functions, lists, data tables
    udm-fields.md              High use UDM fields by detection category
    tuning-checklist.md        Pre submit review for performance and false positives
  examples/
    01_single_event_certutil_download.yaral
    02_sequence_bruteforce_then_success.yaral
    03_absence_edr_sensor_offline.yaral
    04_data_table_device_code_signin.yaral
  rules/                       Community contributed rules
  fixtures/
    _template.json             Copy this to add a test case
    AZURE_AD/ OKTA/ WINDOWS_SYSMON/
                               Sanitized events + parser UDM output, per log type
  scripts/
    lint_rule.py               Offline structural linter (Python 3, no dependencies)
    check_fixtures.py          Checks rules against parser fixtures
```

## Linter

```bash
python3 skills/yara-l-authoring/scripts/lint_rule.py my_rule.yaral
```

It checks:

1. Section order and required sections
2. `metadata.event_type` values against the UDM enum
3. Integer fields compared to quoted strings
4. Event variables that never join to a `match` placeholder
5. Outcome fields missing an aggregate in rules with `match`
6. Absence conditions without a `match` section
7. Regex patterns that start with `.*`
8. Missing meta keys and `$risk_score`

A clean lint result does not mean the rule compiles. Always validate in the SecOps Rules Editor or through the SecOps API before enabling a rule.

## Parser fixtures

Valid syntax and a rule that fires are two different things. A rule can pass the linter and still never fire because your parser writes `FAIL` where the rule expects `BLOCK`.

Fixtures close that gap. Each one is a sanitized raw log, the UDM event a specific parser produced from it, and the rule that should or should not fire.

```bash
python3 skills/yara-l-authoring/scripts/check_fixtures.py
```

```
[FAIL] fixtures/OKTA/bruteforce_then_success_fire.json
  error:   $fail: 0 event(s) match its conditions, rule needs #fail >= 10
  error:     security_result.action: rule wants = 'BLOCK', fixture has ['ALLOW', 'FAIL']
```

The checker confirms every field the rule uses exists in the fixture, compares literal values and regex conditions, checks `#var` thresholds, and rejects fixtures with public IPs, real email domains, or real GUIDs.

The fixtures in this first release are synthetic and marked `verified_against_tenant: false`. Real events from your tenant are the most valuable thing you can contribute. See [fixtures/README.md](skills/yara-l-authoring/fixtures/README.md).

## Limits

1. UDM field population varies by parser. Rules mark uncertain fields with `// VERIFY:`, and fixtures show what specific parsers emit.
2. Example rules use placeholder product names and table names. Replace them before you deploy.
3. New rules should run with alerting off for 7 days while you review detection volume.

## Contributing

The most useful contributions are parser fixtures from real tenants and parser mismatch reports. See [CONTRIBUTING.md](CONTRIBUTING.md), or open a "Parser mismatch" issue if you don't have time for a PR.

## License

MIT. See [LICENSE](LICENSE).

YARA-L, Google Security Operations, and Chronicle are trademarks of Google LLC. This project is not affiliated with or endorsed by Google.
