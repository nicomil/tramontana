#!/usr/bin/env bash
# Copies the working tree to the Windows build machine and runs a command there.
#   scripts/remote.sh dotnet test
#   scripts/remote.sh --no-sync dotnet run --project src/WinCleaner.Cli -- junk
# The host comes from WC_HOST (default: blackframe-minipc, see ~/.ssh/config).
set -euo pipefail
HOST=${WC_HOST:-blackframe-minipc}
STAGE='C:\dev\wcstage'
WORK='C:\dev\wincleaner'
SSH=(ssh -o BatchMode=yes -o LogLevel=ERROR "$HOST")
cd "$(dirname "$0")/.."

sync=1
if [[ "${1:-}" == "--no-sync" ]]; then sync=0; shift; fi

if (( sync )); then
  # Stage a fresh copy, then mirror it into the work folder keeping build outputs.
  COPYFILE_DISABLE=1 tar --no-mac-metadata -cf - \
      --exclude='./.git' --exclude='bin' --exclude='obj' --exclude='artifacts' --exclude='.DS_Store' . |
    "${SSH[@]}" "(if exist $STAGE rmdir /s /q $STAGE) & mkdir $STAGE && tar -xf - -C $STAGE && (robocopy $STAGE $WORK /MIR /XD bin obj artifacts /NFL /NDL /NJH /NJS /NP >nul & exit 0)"
fi

if (( $# )); then
  "${SSH[@]}" "chcp 65001 >nul & set DOTNET_CLI_TELEMETRY_OPTOUT=1& set DOTNET_NOLOGO=1& cd /d $WORK && $*"
fi
