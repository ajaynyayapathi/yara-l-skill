# Community Rules

Contributed YARA-L 2.0 rules go here, one rule per `.yaral` file.

Each rule needs:

1. Every meta field `lint_rule.py` checks for
2. `// VERIFY:` comments on any field you couldn't confirm against a real parser
3. At least one `fire` and one `no_fire` fixture under `fixtures/<LOG_TYPE>/`

See [CONTRIBUTING.md](../../../CONTRIBUTING.md).
