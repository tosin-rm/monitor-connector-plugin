# Proposed security report contract for Monitor

**Status: proposal only; opt-in.** This repository does not contain the Monitor receiver. The Connector emits schema `1.0` by default, without the `security` object. Enable schema `1.1` only after the paired Monitor receiver has been updated and verified to accept and persist the contract below. Set the WordPress filter `monitor_connector_schema_version` to return `'1.1'` for that deployment. Do not deploy a receiver that rejects schema `1.1` or silently interprets security status as clean. Plugin version is `1.1.0`.

## Report version 1.1

The existing report fields remain: `schema_version`, `request_id`, `collected_at`, `wordpress_version`, `plugins`, and `spam_comment_count`. Each plugin has `slug`, `name`, `version`, `active`, `update_available`, and `update_version`.

New fields:

```json
{
  "security": {
    "vulnerability_data": {
      "status": "unavailable",
      "source": null,
      "checked_at": null,
      "findings": [],
      "note": "No approved vulnerability source is configured on this site; Monitor should perform central lookups using plugin slug and installed version."
    },
    "suspicious_activity": {
      "status": "unsupported",
      "source": null,
      "findings": []
    },
    "last_successful_scan_at": null,
    "scan_status": "unsupported"
  }
}
```

This plugin has no vulnerability feed/provider integration and no malware/security scanner integration. Therefore it must not emit vulnerability findings, suspicious activity findings, or a scan completion time. The explicit unavailable/unsupported values prevent absent data from being interpreted as a clean scan. The `note` is explanatory only; receivers should key their logic on status values.

## Receiver behavior and proposed future fields

The Monitor receiver should persist the status fields distinctly and expose them as unknown/unavailable, not “safe”. Suggested status enum:

| Status | Meaning |
| --- | --- |
| `completed` | Source ran successfully and its result is complete; `findings` may be empty or non-empty. |
| `stale` | A previously successful result exists but exceeds Monitor's freshness policy. |
| `unavailable` | Expected source could not be reached or data could not be obtained. |
| `not_run` | A supported source exists but has not completed a run. |
| `unsupported` | No supported integration/source is configured. |
| `error` | A supported source ran but failed to produce a valid result. |

For a future plugin-sourced vulnerability integration, each normalized finding must contain `plugin_slug`, `installed_version`, `advisory_id`, `severity`, `fixed_version` (nullable), `source`, and `checked_at`. Only allow explicitly approved and documented sources. Prefer Monitor-side lookup instead: it can use its own provider configuration and deduplicate/cache lookups centrally. The Connector already reports slug and version for every installed plugin; Monitor can key matching on those fields without requesting credentials from each WordPress site.

For a future scanner integration, define a named, documented adapter and explicit supported versions before enabling it. Each finding should contain a stable finding/advisory identifier, severity, source/scanner name, and checked/completed time, without raw logs, file contents, personal data, IP addresses, or credentials. `scan_status: completed` with an empty findings array means the scanner completed and found nothing. `last_successful_scan_at` is populated only from the scanner's confirmed successful completion metadata; inventory/report timestamps do not qualify. Until such an adapter is implemented, `unsupported` and `null` are required.

## Receiver API changes required

1. Accept schema version `1.1` at the existing authenticated report endpoint, retaining support for `1.0` during a compatibility window if already deployed.
2. Validate and persist the new `security` object and status enums; preserve null timestamps and empty findings as distinct from a completed clean scan.
3. Continue verifying HMAC over the exact raw body, timestamp tolerance, one-time request ID, connection ownership, rate limits, and payload-size bounds before processing.
4. Prefer central vulnerability matching against `plugins[].slug` and `plugins[].version`. If Monitor adds lookup results to its own view/storage, label source, checked time, freshness and lookup errors; do not require WordPress provider secrets.
5. Add UI/API states for unknown/unavailable, unsupported, stale, completed with findings, and completed with no findings. Never map missing values to “no vulnerabilities” or “no suspicious activity”.

## Sample complete report

```json
{
  "schema_version":"1.1",
  "request_id":"a9c73ac7-4af0-4d8d-87c4-136474eb837f",
  "collected_at":"2026-01-02T03:04:05Z",
  "wordpress_version":"6.7.1",
  "plugins":[{"slug":"hello-dolly","name":"Hello Dolly","version":"1.7.2","active":false,"update_available":null,"update_version":null}],
  "spam_comment_count":2,
  "security":{
    "vulnerability_data":{"status":"unavailable","source":null,"checked_at":null,"findings":[],"note":"No approved vulnerability source is configured on this site; Monitor should perform central lookups using plugin slug and installed version."},
    "suspicious_activity":{"status":"unsupported","source":null,"findings":[]},
    "last_successful_scan_at":null,
    "scan_status":"unsupported"
  }
}
```

## Limitations

The Connector reports source state only; it does not assess vulnerability advisories or scan for malware. WordPress plugin update metadata is not a vulnerability feed. A WordPress update being unavailable, or a plugin being up to date, does not mean the plugin has no known vulnerability. No scanner APIs are assumed or scraped.
