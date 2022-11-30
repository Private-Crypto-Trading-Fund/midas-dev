"""
Utilities sort-of-copied from `midas_utils` to avoid an inconvenient circular dependency.
"""
from __future__ import annotations

import configparser
import datetime
import io
from collections.abc import Iterable, Sequence
from typing import TypeVar, cast

TCfgScalar = int | float | bool | str | datetime.date | datetime.datetime  # `toml` scalars
# Note: section can be a scalar, e.g. `toml.loads("x=1") == {"x": 1}`
TCfgSection = dict[str, "TCfgSection"] | list["TCfgSection"] | TCfgScalar
# Tehnically, any `TCfg` is also a `TCfgSection`, but mypy doesn't catch on that.
TCfg = dict[str, TCfgSection]
TVal = TypeVar("TVal")


def pair_window(iterable: Iterable[TVal]) -> Iterable[tuple[TVal, TVal]]:
    """
    >>> list(pair_window([11, 22, 33, 44]))
    [(11, 22), (22, 33), (33, 44)]
    """
    iterable = iter(iterable)
    try:
        prev_value = next(iterable)
    except StopIteration:
        return

    for item in iterable:
        yield prev_value, item
        prev_value = item


def getitem_path(node: TCfg, path: Sequence[str]) -> TCfgSection:
    current: TCfg | TCfgSection = node
    for idx, path_piece in enumerate(path):

        if not isinstance(current, dict):
            raise TypeError(f"Not a `dict` at {path[:idx + 1]}: {type(current)}")

        current = current[path_piece]

    return current


def deep_merge(target: TCfg, updates: TCfg) -> TCfg:
    """
    >>> target = dict(a=1, b=dict(c=2, d=dict(e="f", g="h"), i=dict(j="k")))
    >>> updates = dict(i="i", j="j", b=dict(c=dict(c2="c2"), d=dict(e="f2")))
    >>> deep_merge(target, updates)
    {'a': 1, 'b': {'c': {'c2': 'c2'}, 'd': {'e': 'f2', 'g': 'h'}, 'i': {'j': 'k'}}, 'i': 'i', 'j': 'j'}
    >>> target == dict(a=1, b=dict(c=2, d=dict(e="f", g="h"), i=dict(j="k")))
    True
    """
    target = target.copy()

    new_value: TCfgSection
    for key, value in updates.items():
        old_value = target.get(key)
        if isinstance(old_value, dict):
            new_value = deep_merge(old_value, cast(TCfg, value))
        else:
            new_value = value
        target[key] = new_value

    return target


def dumps_configparser(data: TCfg, strict: bool = False) -> str:
    """Write a `configparser` ("ini") format file"""
    config_obj = configparser.ConfigParser()

    for section_name, section_cfg in data.items():

        if not isinstance(section_cfg, dict):
            if strict:
                raise TypeError(f"Section at {section_name!r} is not a dict: {type(section_cfg)!r}")
            continue

        config_obj[section_name] = {
            key: (
                ", ".join(str(val_item) for val_item in val)
                if isinstance(val, list)
                else val.isoformat()
                if isinstance(val, (datetime.date, datetime.datetime))
                else str(val)
            )
            for key, val in section_cfg.items()
            if not isinstance(val, dict)
        }

    fobj = io.StringIO()
    config_obj.write(fobj)
    return fobj.getvalue()
