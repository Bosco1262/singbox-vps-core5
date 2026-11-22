# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

class SBox5Error(Exception):
    pass


class ConfigError(SBox5Error):
    pass


class VerificationError(SBox5Error):
    pass


class ConflictError(SBox5Error):
    pass


class ExternalCommandError(SBox5Error):
    pass
