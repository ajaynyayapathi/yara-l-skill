# High Use UDM Fields

The Unified Data Model (UDM) normalizes every log source. Parsers differ in which fields they fill, so treat this list as a starting point. Confirm field population against a real event from the user's tenant before you rely on a field.

## Nouns

Every event describes activity between nouns. Most fields hang off one of these.

| Noun | Meaning |
|---|---|
| `principal` | Who or what started the activity |
| `src` | Source of the object being acted on (e.g. file copy source) |
| `target` | Who or what the activity acted on |
| `intermediary` | Proxy, relay, or gateway in the path |
| `observer` | Device that saw and logged the event (e.g. a sensor) |
| `about` | Anything else the event references |

## Event metadata

| Field | Notes |
|---|---|
| `metadata.event_type` | Enum. Filter on it first. |
| `metadata.product_name` | Product as named by the parser |
| `metadata.vendor_name` | Vendor |
| `metadata.log_type` | Ingestion label (e.g. `WINDOWS_SYSMON`, `OKTA`) |
| `metadata.product_event_type` | Raw event ID or name from the source (e.g. `4625`) |
| `metadata.event_timestamp.seconds` | Event time, for ordering |
| `metadata.id` | Unique event ID, use inside `count()` |

Common `metadata.event_type` values: `USER_LOGIN`, `USER_LOGOUT`, `USER_CREATION`, `USER_CHANGE_PERMISSIONS`, `USER_RESOURCE_ACCESS`, `PROCESS_LAUNCH`, `PROCESS_TERMINATION`, `PROCESS_INJECTION`, `FILE_CREATION`, `FILE_MODIFICATION`, `FILE_DELETION`, `NETWORK_CONNECTION`, `NETWORK_DNS`, `NETWORK_HTTP`, `REGISTRY_CREATION`, `REGISTRY_MODIFICATION`, `SERVICE_CREATION`, `SCHEDULED_TASK_CREATION`, `EMAIL_TRANSACTION`, `STATUS_UPDATE`, `RESOURCE_CREATION`, `RESOURCE_PERMISSIONS_CHANGE`, `RESOURCE_DELETION`, `GENERIC_EVENT`.

## Identity and authentication

| Field | Notes |
|---|---|
| `target.user.userid` | Account being logged into or changed |
| `target.user.email_addresses` | Repeated |
| `principal.user.userid` | Actor account |
| `principal.ip` | Repeated. Source IP of the login. |
| `principal.location.country_or_region` | GeoIP, if enriched |
| `target.application` | App or service signed into |
| `security_result.action` | Repeated. `ALLOW`, `BLOCK`, `FAIL`, `CHALLENGE`. Parsers differ on `BLOCK` vs `FAIL` for failed logins. |
| `security_result.summary` | Human readable outcome |
| `extensions.auth.type` | Auth type enum (e.g. `SSO`, `MACHINE`) |
| `extensions.auth.mechanism` | Repeated. Mechanism (e.g. `INTERACTIVE`, `NETWORK`, `REMOTE_INTERACTIVE`) |
| `extensions.auth.auth_details` | Free text detail, parser dependent |

## Process execution

| Field | Notes |
|---|---|
| `target.process.file.full_path` | Launched binary |
| `target.process.command_line` | Full command line |
| `target.process.file.sha256` | Hash of launched binary |
| `principal.process.file.full_path` | Parent process |
| `principal.process.command_line` | Parent command line |
| `principal.hostname` | Host where it ran |
| `principal.user.userid` | User that ran it |

## Network

| Field | Notes |
|---|---|
| `principal.ip`, `target.ip` | Repeated |
| `target.port` | Integer, never quote it |
| `network.ip_protocol` | Enum (`TCP`, `UDP`) |
| `network.application_protocol` | Enum (`DNS`, `HTTP`, `HTTPS`) |
| `network.sent_bytes`, `network.received_bytes` | Unsigned integers |
| `network.dns.questions.name` | Repeated. Queried domain. |
| `target.hostname` | Destination host |
| `target.url` | Full URL for HTTP events |
| `network.http.user_agent` | User agent |

## File and registry

| Field | Notes |
|---|---|
| `target.file.full_path` | File acted on |
| `target.file.sha256` | Hash |
| `target.registry.registry_key` | Key path |
| `target.registry.registry_value_name` | Value name |
| `target.registry.registry_value_data` | Value data |

## Cloud control plane

| Field | Notes |
|---|---|
| `target.resource.name` | Resource acted on |
| `target.resource.resource_type` | Enum, e.g. `SERVICE_ACCOUNT`, `STORAGE_BUCKET` |
| `target.cloud.project.name` | GCP project or equivalent |
| `metadata.product_event_type` | API method (e.g. `google.iam.admin.v1.CreateServiceAccountKey`) |
| `principal.user.userid` | Calling identity, often a service account |

## Unmapped data

When a parser has no UDM home for a value it may land in:

1. `additional.fields`: key/value pairs
2. `security_result.detection_fields`: key/value pairs
3. `principal.resource.attribute.labels` and similar label maps

Access key/value fields like this:

```yara
$e.additional.fields["authenticationProtocol"] = "deviceCode"
```

Mark any rule that depends on these with `// VERIFY:` because they change when parsers are updated.
