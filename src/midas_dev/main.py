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


def dumps_configparser(data: dict[Any, Any]) -> str:
    """Write a `configparser` ("ini") format file"""
    config_obj = configparser.ConfigParser()
    for section_name, section_cfg in data.items():
        config_obj[section_name] = {
            key: ", ".join(val) if isinstance(val, list) else val
            for key, val in section_cfg.items()
            if not isinstance(val, dict)
        }
    fobj = io.StringIO()
    config_obj.write(fobj)
    return fobj.getvalue()


class CLIToolBase:
    def run(self) -> None:
        raise NotImplementedError

    @classmethod
    def run_cli(cls) -> None:
        return cls().run()


class CommonCLITool(CLIToolBase):
    tool_name: str
    config_flag: str
    should_add_default_path: bool = False
    ignored_args: frozenset[str] = frozenset(["--check"])
    config_ext: str = "toml"

    def dumps_config(self, data: dict[Any, Any]) -> str:
        return toml.dumps(data)

    @contextlib.contextmanager
    def merged_config(
        self,
        local_path: str | Path = "pyproject.toml",
        common_config: dict[Any, Any] = MAIN_CONFIG,
    ) -> Generator[Path, None, None]:
        local_config = toml.loads(Path(local_path).read_text())
        full_config = deep_update(common_config, local_config)
        full_config_s = self.dumps_config(full_config)

        target_path = Path(f"./.tmp_config.{self.config_ext}")
        target_path.write_text(full_config_s)
        try:
            yield target_path
        finally:
            target_path.unlink()

    def run_cmd(self, cmd: Sequence[str]) -> None:
        cmd_s = shlex.join(cmd)
        click.echo(f"Running:    {cmd_s}", err=True)
        ret = subprocess.call(cmd)
        if ret:
            click.echo(f"Command returned {ret}", err=True)
            sys.exit(ret)

    def poetry_cmd(self, *parts: str) -> Sequence[str]:
        return ["poetry", "run", "python", "-m", *parts]

    def add_default_path(self, extra_args: Sequence[str], path: str = ".") -> Sequence[str]:
        # A very approximate heuristic: do not add path if any non-flags are present.
        # TODO: a better heuristic.
        if any(not arg.startswith("-") for arg in extra_args):
            return extra_args
        return [*extra_args, path]

    def tool_extra_args(self) -> Sequence[str]:
        return []

    def make_cmd(self, config_path: Path, extra_args: Sequence[str] = ()) -> Sequence[str]:
        if self.should_add_default_path:
            extra_args = self.add_default_path(extra_args)
        if self.ignored_args:
            extra_args = [arg for arg in extra_args if arg not in self.ignored_args]
        return self.poetry_cmd(self.tool_name, self.config_flag, str(config_path), *self.tool_extra_args(), *extra_args)

    def run(self) -> None:
        with self.merged_config() as config_path:
            cmd = self.make_cmd(config_path=config_path, extra_args=sys.argv[1:])
            self.run_cmd(cmd)


class ISort(CommonCLITool):
    tool_name: str = "isort"
    config_flag: str = "--settings"
    should_add_default_path: bool = True
    ignored_args: frozenset[str] = CommonCLITool.ignored_args - {"--check"}


class Black(CommonCLITool):
    tool_name: str = "black"
    config_flag: str = "--config"
    should_add_default_path: bool = True
    ignored_args: frozenset[str] = CommonCLITool.ignored_args - {"--check"}


class Flake8(CommonCLITool):
    tool_name: str = "flake8"
    config_flag: str = "--config"
    config_ext: str = "cfg"  # as in `setup.cfg`

    def dumps_config(self, data: dict[Any, Any]) -> str:
        return dumps_configparser({"flake8": data["tool"]["flake8"]})


class Mypy(CommonCLITool):
    tool_name: str = "mypy"
    config_flag: str = "--config-file"


class Pytest(CommonCLITool):
    tool_name: str = "pytest"
    config_flag: str = "-c"

    def tool_extra_args(self) -> Sequence[str]:
        return ["--doctest-modules"]


class CLIToolWrapper(CLIToolBase):
    wrapped: tuple[type[CLIToolBase], ...]

    def run(self) -> None:
        for tool in self.wrapped:
            tool.run_cli()


class Format(CLIToolWrapper):
    wrapped: tuple[type[CLIToolBase], ...] = (ISort, Black)


class Fulltest(CLIToolWrapper):
    wrapped: tuple[type[CLIToolBase], ...] = (ISort, Black, Flake8, Mypy, Pytest)
