# Parser Fixtures

A fixture is one sanitized log event, the UDM event a specific SecOps parser produced from it, and the rule that should or should not fire on it.

The linter answers "is this rule written correctly?" Fixtures answer a second question: "does this rule match what this parser actually emits?" A rule can pass the linter and still never fire because your parser writes `FAIL` where the rule expects `BLOCK`.

## Layout

One folder per ingestion label (`metadata.log_type`). One JSON file per test case.

```
fixtures/
  _template.json
  AZURE_AD/
    device_code_signin_fire.json
    device_code_signin_approved_no_fire.json
  OKTA/
  WINDOWS_SYSMON/
```

Name files `<behavior>_fire.json` or `<behavior>_no_fire.json`.

## Fixture format

| Key | Required | Meaning |
|---|---|---|
| `description` | Yes | One sentence on what happened |
| `log_type` | Yes | Ingestion label. Must match the folder name. |
| `parser` | Yes | `{"name": ..., "version": ...}`. Use the export date if you don't know the version. |
| `rule` | Yes | Rule name from `examples/` or `rules/` |
| `expect` | Yes | `"fire"` or `"no_fire"` |
| `verified_against_tenant` | Yes | `true` only if the UDM came from a real SecOps tenant |
| `raw_logs` | Yes | List of sanitized raw logs, as JSON objects or strings |
| `udm_events` | Yes | List of UDM events the parser produced, in the same order |
| `relies_on_exclusion` | no_fire only | Name the list, data table, or window that suppresses it |
| `notes` | No | Parser quirks, renamed fields, removed fields |

Field names can be snake_case (`event_type`) or camelCase (`eventType`) as exported by the SecOps API. The checker converts camelCase automatically. Keys inside map fields such as `additional.fields` keep their original spelling.

## Synthetic vs verified

Every fixture shipped in the first release has `verified_against_tenant: false`. They were built from public schema docs to show the format. They are a starting point and may not match your parser.

The most valuable contribution is replacing one of them with a real event from your tenant and setting the flag to `true`.

## How to get a UDM event from your tenant

1. In SecOps, run a UDM search that finds the event.
2. Open the event and switch to the raw log and UDM views.
3. Copy both into the template.
4. Sanitize (see below).
5. Run the checker.

## Sanitizing

The checker fails a fixture that contains any of these:

| Data | Replace with |
|---|---|
| Public IPv4 | `192.0.2.x`, `198.51.100.x`, or `203.0.113.x` (RFC 5737) |
| Email or UPN | `name@example.com` |
| GUID (tenant, object, app, request IDs) | `00000000-0000-0000-0000-00000000000N` |

The checker warns on private IPs (`10.x`, `172.16.x`, `192.168.x`). Replace them too if they reveal your internal addressing.

The checker can't detect these, so remove them by hand:

1. Hostnames and domain names. Use `host-0001.corp.example.com`.
2. Usernames without an `@`. Use `jdoe`.
3. Company, tenant, and project names.
4. API keys, tokens, session IDs, and cookies. Delete the field or set it to `"REDACTED"`.
5. File paths that include a real user's profile name.

Keep the structure intact. Change values, never key names. A renamed key defeats the purpose of the fixture.

## Run the checker

```bash
python3 scripts/check_fixtures.py                       # all fixtures
python3 scripts/check_fixtures.py fixtures/OKTA/*.json  # one log type
```

Example of a parser mismatch it catches:

```
[FAIL] fixtures/OKTA/bruteforce_then_success_fire.json
  error:   $fail: 0 event(s) match its conditions, rule needs #fail >= 10
  error:     security_result.action: rule wants = 'BLOCK', fixture has ['ALLOW', 'FAIL']
```

## What the checker does not do

It is a field and value check, not a rule engine. It ignores match windows, timestamp ordering, reference lists, data tables, functions other than `re.regex`, and outcome logic. Only the SecOps compiler and a retrohunt prove a rule works.
