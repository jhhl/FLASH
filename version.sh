#!/bin/bash

command -v xxd >/dev/null || { echo "xxd not found"; exit 1; }

# [fix.b][feature.b][release.h]
VERSION="04010007" # hex

if [ `git diff-index --quiet HEAD --` ]; then
  HASH=$(printf "0%s" $(git rev-parse --short HEAD))
else 
  HASH=$(printf '%x\n' $(date +%s))
fi

echo "001C: $VERSION $HASH" | xxd -r - $1
