# Monitor Connector

Standalone WordPress plugin source is in [`monitor-connector/`](monitor-connector/). It reports a bounded, read-only inventory to one paired Monitor website.

## Build a ZIP

From the repository root:

```sh
./package.sh
```

This produces `dist/monitor-connector.zip`. The script excludes tests and development files. To install, upload that ZIP via **Plugins → Add New → Upload Plugin** or copy the directory into `wp-content/plugins`.

For full setup, permissions, scheduling, troubleshooting, API contract, a sample signed request shape, and security assumptions, see [`monitor-connector/readme.txt`](monitor-connector/readme.txt).

Run the lightweight pure PHP contract checks with `php monitor-connector/tests/test-contract.php`.
