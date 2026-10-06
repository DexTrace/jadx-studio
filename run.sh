#!/usr/bin/env bash
# Build if needed, then run JADX Studio.
#   ./run.sh                    -> GUI
#   ./run.sh --gui app.apk      -> GUI with a file
#   ./run.sh -o out app.apk     -> CLI
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x build/install/jadx-studio/bin/jadx-studio ]; then
  echo "[*] building (first run)..."
  if [ -x ./gradlew ]; then
    ./gradlew installDist -q
  else
    gradle installDist -q
  fi
fi

exec build/install/jadx-studio/bin/jadx-studio "$@"