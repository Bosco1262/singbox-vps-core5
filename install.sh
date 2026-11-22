#!/usr/bin/env bash
# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if (($# == 0)); then
  set -- install
fi
exec bash "$ROOT/sbox5" "$@"
