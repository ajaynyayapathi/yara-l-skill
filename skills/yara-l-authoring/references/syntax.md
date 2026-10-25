# YARA-L 2.0 Syntax Reference

Condensed reference for writing rules. When something here conflicts with the official Google SecOps documentation, the documentation wins.

## Section order

Sections must appear in this order. Rules require `meta`, `events`, and `condition`.

| Order | Section | Rule | Purpose |
|---|---|---|---|
| 1 | `meta` | Required | Key/value metadata: author, severity, ATT&CK mapping |
| 2 | `events` | Required | Filters and joins on UDM events, entities, or detections |
| 3 | `match` | Optional | Group by placeholders over a time window |
| 4 | `outcome` | Optional | Output variables, up to 20, including `$risk_score` |
| 5 | `condition` | Required | Logic that decides whether the rule fires |
| 6 | `options` | Optional | Rule behavior switches |

```yara
rule rule_name {
  meta:
    author = "you"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  match:
    $user over 10m
  outcome:
    $risk_score = 50
  condition:
    $e
}
```

## Choosing a rule shape

| Shape | When | Key markers |
|---|---|---|
| Single event | One event proves the behavior | No `match`, condition `$e` |
| Multi event count | Threshold over a window | `match` + `#e >= N` |
| Multi event sequence | A then B by the same entity | Two variables joined on a placeholder, timestamp ordering, `match` |
| Absence | A happened and B did not | `match` + `$a and !$b` |
| Composite | Correlate other rules' detections | Detection fields as inputs in `events` |

Rules with no `match` section, or with a `match` section whose condition only checks for one event (`$e`, `#e > 0`, `#e >= 1`), run as single event rules.

## Events section

### Event variables

`$e`, `$fail`, `$proc`: any name after `$`. Each variable is one event. Every line referencing the same variable applies to the same event.

### Placeholders

A placeholder is a variable assigned from a field. Reusing it across event variables creates a join.

```yara
$fail.target.user.userid = $user
$success.target.user.userid = $user
```

Every event variable in a multi event rule must connect to the others through placeholders that appear in `match`.

### Ordering events

```yara
$a.metadata.event_timestamp.seconds < $b.metadata.event_timestamp.seconds
```

### Operators

| Operator | Example |
|---|---|
| `=`, `!=` | `$e.metadata.event_type = "PROCESS_LAUNCH"` |
| `<`, `<=`, `>`, `>=` | `$e.target.port >= 1024` |
| `nocase` | `$e.principal.user.userid = "admin" nocase` |
| `not` | `not $e.principal.hostname = "build01"` |
| `and`, `or` | Lines are implicitly AND. Use `or` with parentheses. |

Strings take double quotes or backticks. Backticks are raw strings: backslashes are not escape characters, which is what you want for regex.

### Repeated fields

Fields like `principal.ip` and `security_result.action` hold lists. A plain comparison matches if any element matches. Use `all` when every element must match:

```yara
any $e.principal.ip = "10.1.1.1"
all $e.security_result.action != "BLOCK"
```

### Common functions

| Function | Use |
|---|---|
| `re.regex(field, \`pattern\`)` | Regex match, returns bool |
| `re.capture(field, \`(group)\`)` | Extract first capture group |
| `strings.lower(s)`, `strings.upper(s)` | Case normalize |
| `strings.concat(a, b, ...)` | Join strings |
| `strings.coalesce(a, b, ...)` | First non empty value |
| `net.ip_in_range_cidr(ip, "10.0.0.0/8")` | CIDR membership |
| `timestamp.get_hour(ts, "UTC")` | Hour of day for off hours logic |
| `timestamp.current_seconds()` | Now, in epoch seconds |
| `math.abs(n)` | Absolute value |
| `arrays.length(list)` | Number of elements in a repeated field |

Check the official function list before using anything not shown here.

### Regex rules

1. Use backtick raw strings.
2. Add `(?i)` for case insensitive.
3. Anchor with `^` and `$` when you can.
4. Avoid leading `.*`; it forces a scan of the whole string on every event.
5. Prefer exact match with `nocase` when the value is fixed.

### Reference lists

Single column lists managed in SecOps. Types: string, regex, CIDR.

```yara
$e.principal.hostname in %admin_workstations
$e.principal.ip in cidr %corp_egress_ranges
$e.target.process.command_line in regex %lolbin_patterns
not $e.principal.user.userid in %service_accounts
```

### Data tables

Multi column lookup tables. Columns are typed string, regex, or CIDR. Data tables are available in rules, search, and dashboards.

Column based comparison (value appears anywhere in the column):

```yara
not $e.target.user.userid in %approved_users.userid
```

Row based comparison (all conditions must hold for the same row):

```yara
$e.target.user.userid = %vip_users.userid
$e.principal.hostname = %vip_users.hostname
```

A rule that references a data table will not save until the table exists.

### Entity graph

Join events to entity context (asset, user, IOC data):

```yara
$e.principal.user.userid = $user
$g.graph.entity.user.userid = $user
$g.graph.metadata.entity_type = "USER"
$g.graph.metadata.source_type = "ENTITY_CONTEXT"
```

## Match section

```yara
match:
  $user over 10m
  $user, $host over 1h
```

Windows: `m`, `h`, `d`. Default to the shortest window that captures the behavior. Larger windows cost more and delay alerts.

## Outcome section

Up to 20 variables. In rules with `match`, any event field must be wrapped in an aggregate.

| Aggregate | Returns |
|---|---|
| `count(x)` | Number of values |
| `count_distinct(x)` | Number of unique values |
| `sum(x)`, `min(x)`, `max(x)` | Numeric summaries |
| `array(x)` | All values |
| `array_distinct(x)` | Unique values, capped |

Conditional values:

```yara
$risk_score = max(if($e.target.user.userid in %vip_users, 90, 60))
```

Special variables:

1. `$risk_score`: integer feeding Risk Analytics.
2. `$risk_entity_to_score`: which entity the score attaches to.

Outcome variables can be used in `condition`:

```yara
condition:
  $e and $unique_hosts > 5
```

## Condition section

| Pattern | Meaning |
|---|---|
| `$e` | At least one `$e` event |
| `#e >= 5` | Five or more `$e` events in the match window |
| `$a and $b` | Both occurred |
| `$a and !$b` | `$a` occurred and `$b` did not (needs `match`) |
| `#fail >= 10 and $success` | Threshold plus sequence |
| `$e and $outcome_var > N` | Threshold on an outcome value |

## Options section

```yara
options:
  allow_zero_values = true
```

`allow_zero_values = true` lets match placeholders be empty. Leave it off unless you have a reason; empty values group unrelated events together.
