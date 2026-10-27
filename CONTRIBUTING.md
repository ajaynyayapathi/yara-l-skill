# Contributing

Thanks for helping. The most useful contributions, in order:

1. **Parser fixtures from a real tenant.** A sanitized event plus the UDM your parser produced. See [fixtures/README.md](skills/yara-l-authoring/fixtures/README.md).
2. **Parser mismatch reports.** Your parser maps a field differently than a rule or the field notes assume. Use the "Parser mismatch" issue template.
3. **New example rules,** each with at least one `fire` and one `no_fire` fixture.
4. **New linter or checker rules** for mistakes you've seen in review.

## Before you open a PR

Run both checks from `skills/yara-l-authoring/`:

```bash
python3 scripts/lint_rule.py examples/*.yaral rules/*.yaral
python3 scripts/check_fixtures.py
```

Both must exit with no errors. Warnings are fine if you explain them in the PR.

## Adding a fixture

1. Copy `fixtures/_template.json` to `fixtures/<LOG_TYPE>/<behavior>_fire.json` or `_no_fire.json`.
2. Paste the raw log and the UDM event from your tenant.
3. Sanitize. The fixture README lists what the checker catches and what you must remove by hand.
4. Set `verified_against_tenant` to `true` and fill in `parser.version`.
5. Run the checker.

If you're correcting a synthetic fixture, edit it in place and set the flag to `true`. Say in the PR what changed.

## Adding a rule

1. Put community rules in `skills/yara-l-authoring/rules/`. The `examples/` folder is for teaching one rule shape each.
2. Include every meta field the linter checks.
3. Mark any field you couldn't confirm with `// VERIFY:`.
4. Add at least one `fire` and one `no_fire` fixture.

## Review checklist

Reviewers check these before merging a fixture:

1. No real IPs, emails, GUIDs, hostnames, usernames, company names, or secrets.
2. Key names unchanged from the parser output.
3. `parser.version` filled in.
4. The checker result matches `expect`.

## Never include

1. Data from an incident you're not authorized to share.
2. Customer data, even sanitized, unless your employer has approved it.
3. Detection logic your employer considers confidential.

When in doubt, build the fixture from a lab tenant.
