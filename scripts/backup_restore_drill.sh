#!/usr/bin/env bash
set -euo pipefail
echo "Backup/restore drill template."
echo "For managed Postgres, automate:"
echo "- trigger snapshot"
echo "- restore to new instance"
echo "- run verification queries"
echo "Record evidence artifacts in docs/evidence/"
