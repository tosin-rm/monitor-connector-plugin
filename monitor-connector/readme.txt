=== Monitor Connector ===
Contributors: monitor-connector
Tags: monitoring, health, inventory
Requires at least: 6.2
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later

Sends a read-only WordPress health inventory to one paired Monitor website.

== Description ==

This plugin reports the WordPress core version, installed plugin identifiers/names/versions/active state/update state, spam comment count, and a UTC collection time. It never sends comment or user records, posts, filesystem data, or credentials. It does not perform WordPress management actions.

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

WordPress update status is taken from WordPress's update_plugins site transient. For a plugin absent from both the response and no_update lists, status is unknown (JSON null). “Disconnect and revoke” attempts remote revocation and always removes the local credential; the resulting notice reports whether Monitor confirmed revocation.

== Troubleshooting ==

Check that the Monitor base URL and endpoint paths match the API contract below, that HTTPS certificates validate, and that the pairing code is current and unused. Non-2xx responses and transport errors are not logged with bodies or secrets. The settings page reports a safe generic failure. Check Monitor-side logs and server connectivity. Ensure the site can run WP-Cron.

== Local development ==

For local development only, HTTP is permitted when the base host is localhost, 127.0.0.1, or ::1. Use an isolated local Monitor server; production URLs must use HTTPS. Endpoint paths are configurable through the settings option (pair_endpoint, report_endpoint, revoke_endpoint); defaults are placeholders and are not claims about an existing Monitor API. No endpoint URL is invented by this plugin.

== Monitor API contract expected ==

Configure a common base URL plus relative endpoint paths. The defaults are `/api/monitor-connector/pair`, `/api/monitor-connector/report`, and `/api/monitor-connector/revoke`; change them for the deployment before pairing if needed.

Pair endpoint: HTTPS POST JSON `{ "pairing_code": "<single-use short-lived code>", "plugin_version": "1.0.0" }`. On success (2xx), return JSON `{ "connection_id": "stable-id", "credential_id": "key-id", "secret": "at-least-32-character-per-site-secret" }`. Pairing code must be consumed atomically and bound to exactly one existing Monitor website. The plugin never retains the pairing code.

Report endpoint: POST the raw JSON body shown below, with headers `X-Monitor-Connection-Id`, `X-Monitor-Key-Id`, `X-Monitor-Timestamp` (Unix seconds), `X-Monitor-Request-Id`, and `X-Monitor-Signature` (`sha256=<lowercase hex HMAC-SHA256(raw body, per-site secret)>`). The request ID in the header must equal the body's request_id. The Monitor server must check freshness, one-time request IDs, constant-time signature equality, connection ownership, schema/field bounds, and rate limits. A 2xx response means accepted; any non-2xx is treated as failure. Report response body is ignored.

Revoke endpoint: signed POST using the same headers over raw JSON `{ "connection_id": "stable-id" }`. Return 2xx only when revocation is confirmed. The plugin removes local credentials regardless of this response.

Sample report payload (values illustrative):

    {"schema_version":"1.0","request_id":"a9c73ac7-4af0-4d8d-87c4-136474eb837f","collected_at":"2026-01-02T03:04:05Z","wordpress_version":"6.7.1","plugins":[{"slug":"hello-dolly","name":"Hello Dolly","version":"1.7.2","active":false,"update_available":null,"update_version":null}],"spam_comment_count":2}

Sample response: `HTTP/1.1 202 Accepted` and `{"accepted":true,"request_id":"a9c73ac7-4af0-4d8d-87c4-136474eb837f"}`. The client intentionally does not consume response content.

== Privacy ==

The privacy policy exporter adds the fields sent, purpose, Monitor-controlled retention, and disconnect instructions. No telemetry or third-party service is used.

== Security review ==

Assumptions: Monitor provides the contract above, uses TLS in production, stores only website-scoped credentials, atomically consumes pairing codes, and enforces replay protection, constant-time signature validation, schema validation and rate limiting. WordPress options are not encrypted by this plugin; database and backups must be protected by the site operator. WP-Cron is best-effort. Update status is unknown when WordPress lacks a definitive update transient record. Inventory fails closed if there are over 500 plugins or serialized payload exceeds 256 KiB. Spam count uses `wp_count_comments()` and does not fetch comment rows. The plugin has no write or management commands and no arbitrary file/database APIs.

