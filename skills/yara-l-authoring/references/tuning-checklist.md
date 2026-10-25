# Pre Submit Review Checklist

Run every rule through this list before you return it. Fix what you can. Report what you cannot.

## Correctness

1. Sections are in order: `meta`, `events`, `match`, `outcome`, `condition`, `options`.
2. `metadata.event_type` uses a valid enum value.
3. Integer fields are compared to integers, strings to strings.
4. Every event variable in a multi event rule joins to the others through a placeholder listed in `match`.
5. Sequence rules order events with `metadata.event_timestamp.seconds`.
6. Absence rules (`!$b`) have a `match` section.
7. Every event field in `outcome` is aggregated when `match` exists.
8. Outcome variable count is 20 or fewer.
9. Every referenced reference list and data table is listed in the output so the user can create it first.
10. Every field marked `// VERIFY:` is listed in the "Fields to verify" output.

## Performance

1. `metadata.event_type` filter is present on every event variable.
2. A product or log type filter narrows the source when the event type is broad (`GENERIC_EVENT`, `NETWORK_CONNECTION`).
3. No regex starts with `.*`.
4. Fixed string matches use `=` with `nocase` instead of regex.
5. Match window is the shortest that fits the behavior. Over 24 hours needs a written reason.
6. `allow_zero_values` is off unless empty values are expected and safe.

## False positives

Name the two most likely benign triggers. Typical sources:

| Detection type | Usual false positive source |
|---|---|
| Brute force | Password expiry, stale tokens on mobile devices, misconfigured service accounts |
| LOLBin execution | Software deployment tools (SCCM, Intune), IT admin scripts |
| Impossible travel | VPN and cloud proxy egress, mobile carriers |
| Privilege change | Change windows, identity governance automation |
| Data exfiltration volume | Backups, sync clients, large legitimate uploads |
| OAuth and device code | Conference room devices, CLI tools, IoT sign ins |

Each exclusion goes into a reference list or data table with a named owner. Never hardcode a hostname or username the SOC will need to change.

## Rollout guidance to include

1. Save the rule with alerting off.
2. Run a retrohunt over the last 7 to 30 days.
3. Review the detection count. More than 20 per day for a medium severity rule usually means tuning is needed before alerting.
4. Enable alerting after the volume is acceptable and an analyst has reviewed 10 sample detections.

## Meta fields required

`author`, `description`, `severity`, `priority`, `mitre_attack_tactic`, `mitre_attack_technique`, `reference`, `rule_version`, `false_positives`, `yara_version`.
