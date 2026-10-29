=== Monitor Connector ===
Contributors: monitor-connector
Tags: monitoring, health, inventory
Requires at least: 6.2
Requires PHP: 7.4
Stable tag: 1.4.0
License: GPLv2 or later

Sends a read-only WordPress health inventory and bounded security inspection results to one paired Monitor website.

== Description ==

This plugin reports WordPress and plugin inventory, spam-comment count, WordPress core checksums, WordPress.org plugin checksums when available, and bounded static PHP pattern inspection across plugins, themes, must-use plugins, and uploads. File contents and user/comment records are never sent. Static pattern matches are leads for review, not proof of malware. This is not an antivirus signature scanner and it does not inspect login/activity logs or perform WordPress management actions. Premium/custom plugins without published checksums and any paths beyond the safety limits are reported as uncovered.

== Installation ==

1. Upload the monitor-connector directory to wp-content/plugins, or install the generated ZIP.
2. Activate Monitor Connector.
3. In Settings → Monitor Connector, enter the Monitor base URL and save.
4. Generate a one-time pairing code for the target website in Monitor and enter it in the pairing field.
5. Send a test report and confirm the inventory in Monitor.

== Permissions ==

Settings actions require the WordPress manage_options capability and action nonces. The plugin stores its connection-specific credential in a non-autoloaded WordPress option. Any administrator able to read database options or backups may be able to access it; protect database backups and hosting access accordingly.

== Scheduling ==

WP-Cron sends reports every 6 hours by default. The interval can be set between 1 and 24 hours. Initial schedule time has up to 15 minutes of jitter. WP-Cron is traffic-driven; sites with low traffic should invoke wp-cron.php from a system scheduler.

== Update and disconnect ==

WordPress update status is taken from WordPress's update_plugins site transient. For a plugin absent from both the response and no_update lists, update_status is `unknown`. “Disconnect and revoke” attempts remote revocation and always removes the local credential; the resulting notice reports whether Monitor confirmed revocation.

== Troubleshooting ==

Check that the Monitor base URL and endpoint paths match the API contract below, that HTTPS certificates validate, and that the pairing code is current and unused. Pairing failures now show a safe diagnostic in Settings → Monitor Connector: transport errors indicate WordPress could not connect over HTTPS, while an HTTP status indicates Monitor received and rejected or failed the request. Response bodies, pairing codes, and credentials are never displayed or logged. Ensure the site can run WP-Cron.

== Local development ==

For local development only, HTTP is permitted when the base host is localhost, 127.0.0.1, or ::1. Use an isolated local Monitor server; production URLs must use HTTPS. Endpoint paths are configurable through the settings option (pair_endpoint, report_endpoint, revoke_endpoint); defaults are placeholders and are not claims about an existing Monitor API. No endpoint URL is invented by this plugin.

== Monitor API contract expected ==

Configure the common Monitor base URL. The default endpoint paths match the Monitor app: `/api/connectors/wordpress/pair`, `/api/connectors/wordpress/report`, and `/api/connectors/wordpress/revoke`. Legacy placeholder paths saved by earlier plugin versions are upgraded automatically.

Pair endpoint: HTTPS POST JSON `{ "pairing_code": "<single-use short-lived code>", "plugin_version": "1.4.0" }`. On success (2xx), return JSON containing `connection_id` and `secret`; the Monitor app may also return `report_url`. Pairing code must be consumed atomically and bound to exactly one existing Monitor website. The plugin never retains the pairing code.

Report endpoint: POST the raw report JSON body, with headers `X-Monitor-Connection`, `X-Monitor-Timestamp` (Unix seconds), `X-Monitor-Request-Id`, and `X-Monitor-Signature` (lowercase hex HMAC-SHA256 over `timestamp.request_id.raw_body`, using the per-site secret). The request ID in the header must equal the body's request_id. The Monitor server checks freshness, one-time request IDs, constant-time signature equality, connection ownership, schema/field bounds, and rate limits. Reports use numeric schema 1.1 by default and include bounded core/plugin checksum results and static code-pattern indicators. Set the `monitor_connector_schema_version` filter to `1.0` only for an older receiver. A 2xx response means accepted; any non-2xx is treated as failure.

Revoke endpoint: signed POST using the same headers over raw JSON `{ "connection_id": "stable-id" }`. Return 2xx only when revocation is confirmed. The plugin removes local credentials regardless of this response.

The default schema 1.1 security report and its coverage boundaries are documented in `SECURITY-REPORT-CONTRACT.md`.

Sample response: `HTTP/1.1 202 Accepted` and `{"accepted":true,"request_id":"a9c73ac7-4af0-4d8d-87c4-136474eb837f"}`. The client intentionally does not consume response content.

== Privacy ==

The privacy policy exporter adds the fields sent, purpose, Monitor-controlled retention, and disconnect instructions. Core and plugin checksums are retrieved from official WordPress.org checksum services. Static inspection reads bounded PHP file contents locally and sends only relative paths, check counts, rule identifiers, and short descriptions for possible indicators. Vulnerability matching is performed centrally by Monitor when its Wordfence feed is configured.

== Security review ==

Assumptions: Monitor provides the contract above, uses TLS in production, stores only website-scoped credentials, atomically consumes pairing codes, and enforces replay protection, constant-time signature validation, schema validation and rate limiting. WordPress options are not encrypted by this plugin; database and backups must be protected by the site operator. WP-Cron is best-effort. Checksum requests use short timeouts and are bounded; only eight uncached plugin checksum documents are fetched per report, and scan coverage is reported when limited or unavailable. Premium/custom plugins often have no public checksum manifest. Static PHP pattern checks can miss malware and can produce false positives; they are not a malware clearance. Update status is unknown when WordPress lacks a definitive update transient record. Inventory fails closed if there are over 500 plugins or serialized payload exceeds 256 KiB. Spam count uses `wp_count_comments()` and does not fetch comment rows. The plugin has no write or management commands and no arbitrary file/database APIs.

