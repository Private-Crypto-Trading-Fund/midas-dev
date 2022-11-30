from __future__ import annotations

import contextlib
import shlex
import subprocess
import sys
from collections.abc import Collection, Generator, Sequence
from pathlib import Path
from typing import Any, ClassVar

import click
import toml

from .utils import TCfg, deep_merge, dumps_configparser, getitem_path, pair_window

HERE = Path(__file__).parent
MAIN_CONFIG = toml.loads((HERE / "common_pyproject.toml").read_text())


def read_local_config(local_path: str | Path = "pyproject.toml") -> TCfg:
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
    concatenate_disable_suffix: ClassVar[str] = "__replace"
    concatenated_list_paths: ClassVar[Collection[Sequence[str]]] = (
        # Makes it possible to add more opts to addopts.
        ("tool", "pytest", "ini_options", "addopts"),
    )

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

    @classmethod
    def merge_configs(cls, common_config: TCfg, local_config: TCfg) -> TCfg:
        result = deep_merge(common_config, local_config)

        # Merge some lists explicitly (unless disabled).
        # Note: expecting all `concatenated_list_paths` paths to exist
        # in the common config (and, thus, in the merged config).
        for concat_path in cls.concatenated_list_paths:
            assert concat_path, "must be non-empty"
            parent_path = concat_path[:-1]
            key = concat_path[-1]
            skip_marker_key = f"{key}{cls.concatenate_disable_suffix}"

            common_value = getitem_path(common_config, concat_path)
            assert isinstance(common_value, list), f"path {concat_path} must point to a list"

            parent = getitem_path(result, parent_path)
            assert isinstance(parent, dict), f"path {parent_path} must point to a dict"
            if skip_marker_key in parent:
                assert parent[skip_marker_key] is True or parent[skip_marker_key] is False
                parent.pop(skip_marker_key)
                continue

            try:
                local_value = getitem_path(local_config, concat_path)
            except KeyError:
                # No local value, nothing to do.
                continue

            assert isinstance(local_value, list), f"path {concat_path} can only be overridden by a list"
            parent[key] = [*common_value, *local_value]

        return result

    @classmethod
    def read_merged_config(
        cls,
        local_path: str | Path = "pyproject.toml",
        common_config: TCfg = MAIN_CONFIG,
    ) -> TCfg:
        local_config = read_local_config()
        return cls.merge_configs(common_config, local_config)

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
        return ["--in-place", "--recursive", "--ignore-init-module-imports", "--remove-all-unused-imports", "--quiet"]


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
