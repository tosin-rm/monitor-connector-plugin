# WordPress security report contract

**Active contract:** Monitor Connector sends schema `1.1` by default. The Monitor report endpoint accepts and persists schema `1.1`. Plugin version is `1.4.0`.

## Report fields

The report includes WordPress version, installed plugin slug/name/version/active/update status, spam-comment count, and a `security` object. No comment contents, usernames, IP addresses, file contents, or credentials are sent.

```json
{
  "security": {
    "vulnerability_data": {
      "status": "unavailable",
      "source": null,
      "checked_at": null,
      "findings": [],
      "note": "Monitor checks installed plugin versions against its centrally synced vulnerability feed."
    },
    "suspicious_activity": {
      "status": "unsupported",
      "source": null,
      "findings": []
    },
    "core_integrity": {
      "status": "complete",
      "source": "wordpress_core_checksums",
      "reason": null,
      "checked_at": "2026-10-29T12:00:00Z",
      "checked_file_count": 1000,
      "modified_file_count": 0,
      "missing_file_count": 0,
      "modified_files": [],
      "missing_files": [],
      "findings_truncated": false
    },
    "software_integrity": {
      "status": "partial",
      "source": "wordpress_org_plugin_checksums",
      "checked_at": "2026-10-29T12:00:00Z",
      "checked_plugin_count": 8,
      "checked_file_count": 1450,
      "unavailable_plugin_count": 4,
      "not_checked_plugin_count": 2,
      "modified_file_count": 0,
      "missing_file_count": 0,
      "modified_files": [],
      "missing_files": [],
      "findings_truncated": false
    },
    "local_file_scan": {
      "status": "complete",
      "source": "monitor_connector_static_checks",
      "coverage": "partial",
      "checked_at": "2026-10-29T12:00:00Z",
      "checked_file_count": 2000,
      "findings": [],
      "findings_truncated": false
    },
    "last_successful_scan_at": null,
    "scan_status": "unsupported"
  }
}
```

## What the checks mean

- **Plugin vulnerabilities:** Monitor, not the WordPress connector, matches installed plugin slugs and versions against the centrally cached Wordfence Intelligence production feed. The Wordfence API key stays in Monitor/worker secrets, never on the WordPress site. Feed matching currently covers plugins; it does not cover WordPress core or themes.
- **Core integrity:** On each report, the connector obtains official checksums for the installed WordPress version and locale, then compares the corresponding core files on disk. It reports up to 100 relative paths for changed or missing files and includes total counts. A mismatch can be a legitimate local edit; it is evidence to review, not proof of compromise. An `unavailable` result includes a safe reason code and is never treated as clean.
- **Plugin integrity:** The connector checks installed plugin files against WordPress.org checksum manifests when available. It fetches at most eight uncached manifests per report, caches manifests for 12 hours, and caps the total number of plugin files checked per report. Premium/custom plugins without public manifests, exhausted limits, and failed requests remain uncovered; the report explicitly counts checked, unavailable, and not-checked plugins. Changed or missing file paths are capped at 100.
- **Local code inspection:** The connector reads PHP files locally from plugins, themes, must-use plugins, and uploads, within limits of 2,000 files and 20 MiB per report. It looks for a small set of high-risk patterns such as encoded content passed to dynamic execution and request parameters used as include paths. Only relative file paths, rule identifiers, and descriptions are reported; source contents are not sent. The check is heuristic, can miss malware, and can flag legitimate code. Partial coverage is marked.
- **Suspicious activity / malware:** The connector does not inspect login history or run an antivirus signature engine. `suspicious_activity` remains `unsupported`; static code findings are reported separately as `local_file_scan` and are not presented as confirmed malware. `scan_status` and `last_successful_scan_at` remain unsupported/null until a dedicated malware or activity-log source is integrated.
- **Unavailable checks:** If official checksum data cannot be obtained or local files cannot be read safely, the corresponding check reports `unavailable` with no success timestamp/findings and a safe reason when available. It never treats an unavailable check as clean.

## Receiver validation

Monitor validates report fields and security statuses, checks future timestamps, verifies the HMAC over the exact raw body, enforces request freshness and replay prevention, and persists reports within the connector's existing retention/RLS boundary. The core-integrity timestamp participates in future-time validation. No database migration is required for this nested JSON report field; the existing report security JSONB column and schema 1.1 RPC persist it.

## Feed setup

Configure `WORDFENCE_INTELLIGENCE_API_KEY` in the Monitor Production environment and the scheduled GitHub Actions worker secrets. Apply migrations `0010_wordpress_security_reports.sql`, `0011_wordpress_vulnerability_feed.sql`, and `0012_wordpress_connector_schema_11.sql` if they are not already applied. Then run `.github/workflows/wordfence-vulnerability-feed.yml` manually once and confirm the feed timestamp on the website security panel. The workflow supports `SUPABASE_SERVICE_ROLE_KEY` or a valid `SUPABASE_SECRET_KEY` as its server-side database credential.
