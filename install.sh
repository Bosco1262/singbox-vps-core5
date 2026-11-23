#!/bin/sh
# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
umask 077
ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ "$#" -eq 0 ]; then
  set -- install
fi
exec sh "$ROOT/sbox5" "$@"
