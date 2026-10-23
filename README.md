# Monitor Connector

Standalone WordPress plugin source is in [`monitor-connector/`](monitor-connector/). It reports a bounded, read-only inventory and explicit unknown/unsupported security-data states to one paired Monitor website. The proposed Monitor receiver changes for schema 1.1 are in [`SECURITY-REPORT-CONTRACT.md`](monitor-connector/SECURITY-REPORT-CONTRACT.md).

## Build a ZIP

From the repository root, run `./package.sh`. This creates `dist/monitor-connector.zip`.

See [`monitor-connector/readme.txt`](monitor-connector/readme.txt) for installation, pairing, permissions, scheduling, troubleshooting, and the API contract. Run contract checks with `php monitor-connector/tests/test-contract.php`.
