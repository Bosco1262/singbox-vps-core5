# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Internationalization and language resolution support.
# 国际化与语言解析支持。

from __future__ import annotations

import locale
import os
import sys
from typing import Sequence

# Supported language codes.
# 支持的语言代码。
LANG_EN = "en"
LANG_ZH = "zh-CN"
SUPPORTED_LANGUAGES = (LANG_EN, LANG_ZH)

# Current active language code.
# 当前激活的语言代码。
_CURRENT_LANGUAGE = LANG_EN


# Normalize raw language string into 'en' or 'zh-CN'.
# 将原始语言字符串规范化为 'en' 或 'zh-CN'。
def normalize_language(raw: str | None) -> str | None:
    if not raw:
        return None
    val = raw.strip().lower().replace("_", "-")
    if val.startswith("zh"):
        return LANG_ZH
    if val.startswith("en"):
        return LANG_EN
    return None


# Extract explicit language argument from command-line arguments.
# 从命令行参数中提取显式指定的语言选项。
def extract_lang_arg(argv: Sequence[str] | None = None) -> str | None:
    args = sys.argv[1:] if argv is None else list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-l", "--lang", "--language"):
            if i + 1 < len(args):
                normalized = normalize_language(args[i + 1])
                if normalized:
                    return normalized
            i += 2
            continue
        for prefix in ("-l=", "--lang=", "--language="):
            if arg.startswith(prefix):
                normalized = normalize_language(arg[len(prefix):])
                if normalized:
                    return normalized
        i += 1
    return None


# Detect language from system environment variables and locale.
# 从系统环境变量和区域设置中自动检测语言。
def detect_system_language() -> str | None:
    for env_var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        val = os.environ.get(env_var)
        detected = normalize_language(val)
        if detected:
            return detected
    try:
        loc = locale.getdefaultlocale()[0]
        detected = normalize_language(loc)
        if detected:
            return detected
    except Exception:
        pass
    return None


# Resolve language following priority:
# 1. Explicit parameter (-l, --lang, --language)
# 2. System / environment auto-detection
# 3. Guaranteed English fallback
#
# 按以下优先级解析语言：
# 1. 显式参数（-l, --lang, --language）
# 2. 系统/环境变量自动检测
# 3. 保证回退到英文
def resolve_language(argv: Sequence[str] | None = None, explicit: str | None = None) -> str:
    # 1. Check explicit manual language parameter.
    # 1. 检查显式指定的手动语言参数。
    normalized = normalize_language(explicit)
    if normalized:
        return normalized

    arg_lang = extract_lang_arg(argv)
    if arg_lang:
        return arg_lang

    # 2. Check automatic system detection.
    # 2. 检查系统环境自动检测。
    detected = detect_system_language()
    if detected:
        return detected

    # 3. Guaranteed fallback to English.
    # 3. 保证回退至英文。
    return LANG_EN


# Set global language.
# 设置全局语言。
def set_language(lang: str) -> None:
    global _CURRENT_LANGUAGE
    normalized = normalize_language(lang)
    _CURRENT_LANGUAGE = normalized if normalized else LANG_EN


# Get current active language.
# 获取当前激活的语言。
def get_language() -> str:
    return _CURRENT_LANGUAGE


# Return localized text based on active language.
# 根据当前激活的语言返回本地化文本。
def tr(en_text: str, zh_text: str) -> str:
    return zh_text if _CURRENT_LANGUAGE == LANG_ZH else en_text
