#!/bin/bash
# Remove everything setup.sh built: $R and nothing else (toolchains and caches included, so
# the next setup.sh downloads them again). Nothing here runs a process, so
# there is nothing to stop.
source "$(dirname "$0")/config.sh"
case "$R" in /private/tmp/?*|/tmp/?*) ;; *) echo "refusing to remove $R: not under /private/tmp" >&2; exit 1 ;; esac
# Go's module cache is read-only on disk.
[ -d "$R" ] && chmod -R u+w "$R" 2>/dev/null
rm -rf "$R"
echo "torn down $R"
