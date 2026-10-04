"""Central string catalog: `t(key, **kw)`.

Merges `strings_common`, `strings_user` and `strings_admin` (one module per owner; a key
defined in two modules is an error at import time). German can be added later as a second
catalog selected by `lang`.

Formatting: `str.format` with the given keyword arguments plus `app_title`, `chair_label`
and `currency` (symbol) from the settings. Unknown keys return the key itself (and log a
warning) so a missing string never breaks a page; tests assert that keys exist.
"""

from __future__ import annotations

import logging
import string

from app import strings_admin, strings_common, strings_mail, strings_site, strings_user
from app.config import get_settings

DEFAULT_LANG = "en"
log = logging.getLogger(__name__)


def _merge(*modules) -> dict[str, str]:
    merged: dict[str, str] = {}
    for module in modules:
        for key, value in module.STRINGS.items():
            if key in merged:
                raise RuntimeError(f"duplicate string key {key!r} in {module.__name__}")
            merged[key] = value
    return merged


CATALOGS: dict[str, dict[str, str]] = {DEFAULT_LANG: _merge(strings_common, strings_user, strings_admin, strings_mail, strings_site)}


class _Defaults(dict):
    def __missing__(self, key):  # leave unknown placeholders visible instead of crashing
        return "{" + key + "}"


def has(key: str, lang: str = DEFAULT_LANG) -> bool:
    return key in CATALOGS.get(lang, CATALOGS[DEFAULT_LANG])


def t(key: str, lang: str = DEFAULT_LANG, **kw) -> str:
    catalog = CATALOGS.get(lang, CATALOGS[DEFAULT_LANG])
    text = catalog.get(key)
    if text is None:
        text = CATALOGS[DEFAULT_LANG].get(key)
    if text is None:
        log.warning("missing string key %r", key)
        return key
    if not any(field for _, field, _, _ in string.Formatter().parse(text) if field is not None):
        return text
    settings = get_settings()
    values = _Defaults(app_title=settings.app_title, chair_label=settings.chair_label,
                       currency=settings.currency_symbol)
    values.update(kw)
    return string.Formatter().vformat(text, (), values)
