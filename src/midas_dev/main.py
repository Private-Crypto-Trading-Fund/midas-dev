from __future__ import annotations

import configparser
import contextlib
import functools
import io
import shlex
import subprocess
import sys
from collections.abc import Callable, Generator, Mapping, Sequence
from pathlib import Path
from typing import Any

import click
import toml

HERE = Path(__file__).parent
MAIN_CONFIG = toml.loads((HERE / "common_pyproject.toml").read_text())


def deep_update(target: dict[Any, Any], updates: Mapping[Any, Any]) -> dict[Any, Any]:
    """
    >>> target = dict(a=1, b=dict(c=2, d=dict(e="f", g="h"), i=dict(j="k")))
    >>> updates = dict(i="i", j="j", b=dict(c=dict(c2="c2"), d=dict(e="f2")))
    >>> deep_update(target, updates)
    {'a': 1, 'b': {'c': {'c2': 'c2'}, 'd': {'e': 'f2', 'g': 'h'}, 'i': {'j': 'k'}}, 'i': 'i', 'j': 'j'}
    """
    target = target.copy()
    for key, value in updates.items():
        old_value = target.get(key)
        if isinstance(old_value, dict):
            new_value = deep_update(old_value, value)
        else:
            new_value = value
        target[key] = new_value
    return target


def dumps_cfg(data: dict[Any, Any], sections: set[str] | None = None) -> str:
    config_obj = configparser.ConfigParser()
    for section_name, section_cfg in data["tool"].items():
        if sections is not None and section_name not in sections:
            continue
        config_obj[section_name] = {
            key: ", ".join(val) if isinstance(val, list) else val
            for key, val in section_cfg.items()
            if not isinstance(val, dict)
        }
    fobj = io.StringIO()
    config_obj.write(fobj)
    return fobj.getvalue()


@contextlib.contextmanager
def merged_config(
    local_path: str | Path = "pyproject.toml",
    common_config: dict[Any, Any] = MAIN_CONFIG,
    dumps_func: Callable[[dict[Any, Any]], str] = toml.dumps,
    ext: str = "toml",
) -> Generator[Path, None, None]:
    local_config = toml.loads(Path(local_path).read_text())
    full_config = deep_update(common_config, local_config)
    full_config_s = dumps_func(full_config)

    target_path = Path(f"./.tmp_config.{ext}")
    target_path.write_text(full_config_s)
    try:
        yield target_path
    finally:
        target_path.unlink()


def run_cmd(cmd: Sequence[str], add_argv: bool = True) -> None:
    if add_argv:
        cmd = [*cmd, *sys.argv[1:]]
    cmd_s = shlex.join(cmd)
    click.echo(f"Running:    {cmd_s}", err=True)
    ret = subprocess.call(cmd)
    if ret:
        click.echo(f"Command returned {ret}", err=True)
        sys.exit(ret)


def run_isort():
    with merged_config() as config_path:
        run_cmd(
            [
                "poetry",
                "run",
                "python",
                "-m",
                "isort",
                "--settings",
                str(config_path),
                ".",
            ]
        )


def run_black():
    with merged_config() as config_path:
        run_cmd(
            [
                "poetry",
                "run",
                "python",
                "-m",
                "black",
                "--config",
                str(config_path),
                ".",
            ]
        )


def run_fmt():
    run_isort()
    run_black()


def run_lint():
    with merged_config(
        dumps_func=functools.partial(dumps_cfg, sections={"flake8"}), ext="cfg"
    ) as config_path:
        run_cmd(
            ["poetry", "run", "python", "-m", "flake8", "--config", str(config_path)]
        )


def run_mypy():
    with merged_config() as config_path:
        run_cmd(
            ["poetry", "run", "python", "-m", "mypy", "--config-file", str(config_path)]
        )


def run_pytest():
    with merged_config() as config_path:
        run_cmd(
            [
                "poetry",
                "run",
                "python",
                "-m",
                "pytest",
                "--doctest-modules",
                "-c",
                str(config_path),
            ]
        )


def run_test():
    run_fmt()
    run_lint()
    run_mypy()
    run_pytest()
