#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$ROOT/dist"
cd "$ROOT"
rm -f dist/monitor-connector.zip
zip -r dist/monitor-connector.zip monitor-connector -x 'monitor-connector/tests/*' 'monitor-connector/.DS_Store'
printf 'Created %s\n' "$ROOT/dist/monitor-connector.zip"
