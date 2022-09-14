from __future__ import annotations

import configparser
import contextlib
import io
import shlex
import subprocess
import sys
from collections.abc import Generator, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, TypeVar

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


def read_local_config(local_path: str | Path = "pyproject.toml") -> dict[str, Any]:
    return toml.loads(Path(local_path).read_text())


class CLIToolBase:
    def run(self) -> None:
        raise NotImplementedError

    @classmethod
    def run_cli(cls) -> None:
        return cls().run()


class CommonCLITool(CLIToolBase):
    tool_name: str
    should_add_default_path: bool = False
    ignored_args: frozenset[str] = frozenset(["--check"])

    def run_cmd(self, cmd: Sequence[str]) -> None:
        cmd_s = shlex.join(cmd)
        click.echo(f"Running:    {cmd_s}", err=True)
        ret = subprocess.call(cmd)
        if ret:
            click.echo(f"Command returned {ret}", err=True)
            sys.exit(ret)

    def poetry_cmd(self, *parts: str) -> Sequence[str]:
        return ["poetry", "run", "python", "-m", *parts]

    @staticmethod
    def has_positional_args(args: Sequence[str]) -> bool:
        # TODO: a better heuristic.
        for prev_arg, arg in pair_window(["", *args]):
            if arg.startswith("-"):
                # assyme an option
                continue
            if prev_arg.startswith("--"):
                # Assume a value for an option
                continue
            return True
        return False

    @staticmethod
    def read_merged_config(
        local_path: str | Path = "pyproject.toml",
        common_config: dict[str, Any] = MAIN_CONFIG,
    ) -> dict[str, Any]:
        local_config = read_local_config()
        return deep_update(common_config, local_config)

    def add_default_path(self, extra_args: Sequence[str], path: str = ".") -> Sequence[str]:
        # A very approximate heuristic: do not add path if any non-flags are present.
        if self.has_positional_args(extra_args):
            return extra_args
        return [*extra_args, path]

    def tool_extra_args(self) -> Sequence[str]:
        return []

    def make_cmd(self, extra_args: Sequence[str] = ()) -> Sequence[str]:
        if self.should_add_default_path:
            extra_args = self.add_default_path(extra_args)
        if self.ignored_args:
            extra_args = [arg for arg in extra_args if arg not in self.ignored_args]
        return self.poetry_cmd(self.tool_name, *self.tool_extra_args(), *extra_args)

    def run(self) -> None:
        cmd = self.make_cmd(extra_args=sys.argv[1:])
        self.run_cmd(cmd)


class ConfiguredCLITool(CommonCLITool):
    config_flag: str
    config_ext: str = "toml"

    def dumps_config(self, data: dict[Any, Any]) -> str:
        return toml.dumps(data)

    @contextlib.contextmanager
    def merged_config(
        self,
        local_path: str | Path = "pyproject.toml",
        common_config: dict[Any, Any] = MAIN_CONFIG,
    ) -> Generator[Path, None, None]:
        full_config = self.read_merged_config()
        full_config_s = self.dumps_config(full_config)

        target_path = Path(f"./.tmp_config.{self.config_ext}")
        target_path.write_text(full_config_s)
        try:
            yield target_path
        finally:
            target_path.unlink()

    def run(self) -> None:
        with self.merged_config() as config_path:
            config_args = [self.config_flag, str(config_path)]
            cmd = self.make_cmd(extra_args=[*config_args, *sys.argv[1:]])
            self.run_cmd(cmd)


class Autoflake(CommonCLITool):
    """
    Note that this wrapper doesn't support common configuration,
    because autoflake doesn't have a `--config` flag,
    so it isn't currently possible to override the extra args this class provides.

    If necessary, this wrapper can be modified use `self.read_merged_config` to
    build the extra args.
    """

    tool_name: str = "autoflake"
    should_add_default_path: bool = True
    ignored_args: frozenset[str] = ConfiguredCLITool.ignored_args - {"--check"}

    def tool_extra_args(self) -> Sequence[str]:
        return ["--in-place", "--recursive", "--ignore-init-module-imports", "--remove-all-unused-imports"]


class ISort(ConfiguredCLITool):
    tool_name: str = "isort"
    config_flag: str = "--settings"
    should_add_default_path: bool = True
    ignored_args: frozenset[str] = ConfiguredCLITool.ignored_args - {"--check"}


class Black(ConfiguredCLITool):
    tool_name: str = "black"
    config_flag: str = "--config"
    should_add_default_path: bool = True
    ignored_args: frozenset[str] = ConfiguredCLITool.ignored_args - {"--check"}


class Flake8(ConfiguredCLITool):
    tool_name: str = "flake8"
    config_flag: str = "--config"
    config_ext: str = "cfg"  # as in `setup.cfg`

    def dumps_config(self, data: dict[Any, Any]) -> str:
        return dumps_configparser({"flake8": data["tool"]["flake8"]})


class Mypy(ConfiguredCLITool):
    tool_name: str = "mypy"
    config_flag: str = "--config-file"


class Pytest(ConfiguredCLITool):
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
    wrapped: tuple[type[CLIToolBase], ...] = (Autoflake, ISort, Black)


class Fulltest(CLIToolWrapper):
    wrapped: tuple[type[CLIToolBase], ...] = (*Format.wrapped, Flake8, Mypy, Pytest)
