#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import functools
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Generator, Iterable, Sequence
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

import toml
import yaml

from midas_dev.utils import deep_merge

HELP = """
Script for one-run (re)deploying.

Recommended usage: deploy a specific version:

    poetry run middeploy v1.2.3

Easier usage: deploy the latest version:

    poetry run middeploy latest

Testing usage: deploy on a specified single host:

    DEPLOY_TARGET_INSTANCES=ubuntu@ec2-1-2-3-4.eu-central-1.compute.amazonaws.com \
    DEPLOY_SSH_OPTIONS="-l ubuntu" \
    poetry run middeploy latest

Run one of the main or extra steps independently:

    poetry run middeploy - check
    poetry run middeploy - initial_setup
    poetry run middeploy - pull_prod_config
    poetry run middeploy - write_prod_config
    poetry run middeploy - set_hostname
    poetry run middeploy - set_up_docker
    poetry run middeploy - set_up_netdata
    poetry run middeploy - set_up_stuff
    poetry run middeploy - initial_setup_reset
    poetry run middeploy - initial_setup_finalize
    poetry run middeploy latest main_setup

WARNING: the CLI format of this is subject to change.

Introduction to a new project:

  * Configure `./pyproject.toml` `[tool.deploy]`:
    * `instances`: space-separated hostnames to deploy onto.
      See `DEPLOY_TARGET_INSTANCES` override example above.
    * `ssh_options`: Optional extra options for `ssh` (and rsync-over-ssh).
      Defaults to `-p 22022 -l ubuntu`.
    * `netdata_claim_token`, `netdata_claim_rooms`, `netdata_sender_endpoint`:
      configuration from https://app.netdata.cloud/
    * `./docker-compose.yaml` should specify development-usable containers.
    * `./deploy/docker-compose.prod.yaml` should specify the production configuration overrides
      (on top of `./docker-compose.yaml`).
      It *must* use `${PROJECT_NAME}_IMAGE_VERSION` env variable for the app images.
      It *must* use `env_file: "$HOME/.config/midas/{projectname}/.env"`.
  * Configure own environment:
    * Docker token into `~/.config/midas/docker_token`
    * Produciton config into `~/.config/midas/${project_name}/.env`
  * Test the deployment on a temporary aws host.

"""

TDeployType = Literal["production", "staging"]

HERE = Path(__file__).parent
LIB_CONFIGS_PATH = HERE / "deploy_data"
DOCKER_REGISTRY_REPO = "investmentsteam"

DOCKER_TOKEN_PATH = Path.home() / ".config/midas/docker_token"


_COMMON_SHELL_HEAD = r"""
set -eux
export LC_ALL=C DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical NEEDRESTART_MODE=a
"""


def _common_raw_command(cmd: str) -> str:
    """Wrap a script into common handling that doesn't require templating"""
    return _COMMON_SHELL_HEAD.strip() + "\n" + cmd.strip()


_COMMON_SHELL_TPL_HEAD_BASE = r"""
export {vervar_spec}
"""
_COMMON_SHELL_TPL_HEAD = _common_raw_command(_COMMON_SHELL_TPL_HEAD_BASE)


def _common_tpl_command(cmd: str) -> str:
    """
    Wrap a script into common handling that **does** require templating
    (and provides a version env variable).
    """
    return _COMMON_SHELL_TPL_HEAD.strip() + "\n" + cmd.strip()


_STATUS_CHECK_TPL_BASE = r"""
if [ -d {prjname_sq} ]; then echo "ok"; else echo "none"; fi
"""
_STATUS_CHECK_TPL = _common_tpl_command(_STATUS_CHECK_TPL_BASE)


_INSTANCE_NAME_SH_BASE = r"""
TOKEN="$(
    curl -Ss --fail-with-body \
        -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
)"
curl -Ss --fail-with-body \
    -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/tags/instance/Name"
"""
_INSTANCE_NAME_SH = _common_raw_command(_INSTANCE_NAME_SH_BASE)


_SET_HOSTNAME_TPL_BASE = r"""
sudo hostnamectl set-hostname {target_hostname_sq}
"""
_SET_HOSTNAME_TPL = _common_raw_command(_SET_HOSTNAME_TPL_BASE)


_SET_UP_DOCKER_TPL_BASE = r"""
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install docker.io docker-compose python3-pip python3-requests -y

sudo groupadd -f docker
sudo usermod -aG docker "$(whoami)"

sudo systemctl enable docker.service
sudo systemctl enable containerd.service
sudo systemctl daemon-reload
sudo systemctl restart docker

"""
_SET_UP_DOCKER_TPL = _common_tpl_command(_SET_UP_DOCKER_TPL_BASE)
_DOCKER_AUTH_TPL_BASE = r"""
echo {docker_token_sq} | docker login --username {docker_username_sq} --password-stdin
"""
_DOCKER_AUTH_TPL = _common_tpl_command(_DOCKER_AUTH_TPL_BASE)

_SET_UP_NETDATA_TPL_BASE = r"""
curl -Ss --fail-with-body \
    "https://my-netdata.io/kickstart.sh" \
    -o /tmp/netdata-kickstart.sh

sh -x /tmp/netdata-kickstart.sh \
    --claim-rooms {nd_claim_rooms_sq} \
    --claim-token {nd_claim_token_sq} \
    --claim-url https://app.netdata.cloud

sudo cp /tmp/_netdata_config/* /etc/netdata/
sudo systemctl restart netdata.service
"""
_SET_UP_NETDATA_TPL = _common_tpl_command(_SET_UP_NETDATA_TPL_BASE)


_SET_UP_STUFF_TPL_BASE = r"""
sudo snap remove amazon-ssm-agent --purge  # does not error-exit if it is not installed
"""
_SET_UP_STUFF_TPL = _common_tpl_command(_SET_UP_STUFF_TPL_BASE)


_INITIAL_SETUP_FINALIZE_TPL_BASE = r"""
mkdir -p ./{prjname_sq}
"""
_INITIAL_SETUP_FINALIZE_TPL = _common_tpl_command(_INITIAL_SETUP_FINALIZE_TPL_BASE)


_MAIN_SETUP_TPL_BASE_TPL = r"""
cd ./{{prjname_sq}}
docker pull {{main_image_sq}}

docker-compose {dc_files} pull --include-deps
docker ps
docker-compose {dc_files} down
docker-compose {dc_files} up --no-build --detach

sleep 7
docker ps
"""
_PROD_CONFIGS_CMD = "-f ./docker-compose.yaml -f ./deploy/docker-compose.prod.yaml"
_STAGING_CONFIGS_CMD = (
    "-f ./docker-compose.yaml -f ./deploy/docker-compose.prod.yaml -f ./deploy/docker-compose.staging.yaml"
)
_MAIN_SETUP_PROD_TPL = _common_tpl_command(_MAIN_SETUP_TPL_BASE_TPL.format(dc_files=_PROD_CONFIGS_CMD))
_MAIN_SETUP_STAGING_TPL = _common_tpl_command(_MAIN_SETUP_TPL_BASE_TPL.format(dc_files=_STAGING_CONFIGS_CMD))


TType = TypeVar("TType")


def ensure_type(value: Any, type_: type[TType]) -> TType:
    """`cast(value, type_)` with runtime `isinstance` validation"""
    if not isinstance(value, type_):
        raise ValueError("Unexpected value type", dict(type_=type_, value=value))
    return value


class NameTagError(Exception):
    pass


class DeployManager:
    """
    Assuming the current directory is the project root.
    """

    def __init__(self) -> None:
        self._sh_tpl_vars: dict[str, str] = {}

    def _sq(self, value: str) -> str:
        return shlex.quote(value)

    def _sh_join(self, items: Iterable[str], sep: str = " ") -> str:
        return sep.join(self._sq(item) for item in items)

    def _conf_value(self, name: str) -> str | None:
        return os.environ.get(name)

    def _request_value(self, title: str) -> str:
        return input(f"{title}: ")

    def _get_docker_token(self) -> str:
        res = self._conf_value("DOCKER_TOKEN")
        if res:
            return res
        if DOCKER_TOKEN_PATH.is_file():
            res = DOCKER_TOKEN_PATH.read_text().strip()
        if res:
            return res
        return self._request_value("Docker pull token")

    @functools.cached_property
    def _pyproj(self) -> dict[str, Any]:
        return toml.load("./pyproject.toml")

    @functools.cached_property
    def _prjname(self) -> str:
        return ensure_type(self._pyproj["tool"]["poetry"]["name"], str)

    @functools.cached_property
    def _app_version_var_name(self) -> str:
        return f"{self._prjname.upper()}_IMAGE_VERSION"  # e.g. SOMEPROJ_IMAGE_VERSION

    @functools.cached_property
    def _app_docker_image(self) -> str:
        return f"{DOCKER_REGISTRY_REPO}/{self._prjname}"

    @functools.cached_property
    def _conf_relpath(self) -> str:
        return f".config/midas/{self._prjname}/.env"

    @functools.cached_property
    def _prod_config_path(self) -> Path:
        return Path.home() / f"{self._conf_relpath}.prod"

    @functools.cached_property
    def _ssh_options(self) -> str:
        return (
            self._conf_value("DEPLOY_SSH_OPTIONS")
            or self._pyproj["tool"]["deploy"].get("ssh_options")
            or "-p 22022 -l ubuntu"
        )

    def get_current_branch(self) -> str:
        return self._sh("git branch --show-current")

    # TODO: caching (but also async).
    def get_deploy_type(self) -> TDeployType | None:
        deploy_type = self._conf_value("DEPLOY_TYPE")
        if deploy_type:
            if deploy_type not in ("production", "staging"):
                raise ValueError(f"Unexpected DEPLOY_TYPE={deploy_type!r}")
            return cast(TDeployType, deploy_type)

        branch = self.get_current_branch()
        branch_to_type: dict[str, TDeployType] = {
            self._pyproj["tool"]["deploy"].get("production_branch") or "master": "production",
            self._pyproj["tool"]["deploy"].get("staging_branch") or "staging": "staging",
        }
        return branch_to_type.get(branch)

    def _log(self, message: str) -> None:
        sys.stderr.write(f"| {message}\n")

    def _sh(self, cmd: str, capture: bool = True, check: bool = True, **kwargs: Any) -> str:
        self._log(f"$ {cmd}")
        res = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE if capture else None, check=check, **kwargs)
        return (res.stdout or b"").decode(errors="replace").rstrip("\n")

    def _ssh(self, instance: str, cmd: str, capture: bool = True) -> str:
        return self._sh(f"ssh  {self._ssh_options}  {self._sq(instance)}  {self._sq(cmd)}", capture=capture)

    def _ssh_check(self, instance: str, cmd: str) -> bool:
        marker = "_MIDDEPLOY_SSH_CHECK_FLAG_"
        # Note that this captures stdout but not stderr (by default).
        res = self._ssh(instance, f"( {cmd}; ) || echo {self._sq(marker)}")
        if marker in res:
            return False
        self._log(f"-> {res!r}")
        return True

    def _rsync_any(self, src: str, dst: str, args: Iterable[str] = (), capture: bool = False, **kwargs: Any) -> str:
        cmd_pieces = [
            "rsync",
            f"--rsh=ssh {self._ssh_options}",
            "--verbose",
            "--recursive",
            *args,
            src,
            dst,
        ]
        cmd = self._sh_join(cmd_pieces)
        return self._sh(cmd, capture=capture, **kwargs)

    def _rsync(
        self, instance: str, src: str = ".", dst: str | None = None, args: Iterable[str] = (), **kwargs: Any
    ) -> str:
        if not dst:
            dst = f"{self._prjname}/"
        return self._rsync_any(src=src, dst=f"{instance}:{dst}", args=args)

    def _sh_tpl(self, tpl: str, extra_vars: dict[str, str] | None = None) -> str:
        return tpl.format(**self._sh_tpl_vars, **(extra_vars or {}))

    def _render_configs(self, path: Path) -> None:
        filenames = ["netdata_python_custom_sender.py", "health_alarm_notify.conf"]
        tpl_replacements = {
            "___PRJNAME___": self._prjname,
            "___ENDPOINT___": self._pyproj["tool"]["deploy"]["netdata_sender_endpoint"],
        }
        for filename in filenames:
            src = LIB_CONFIGS_PATH / filename
            content = src.read_text()
            for tpl_text, res_text in tpl_replacements.items():
                content = content.replace(tpl_text, res_text)
            dst = path / filename
            dst.write_text(content)

    @contextlib.contextmanager
    def _config_files(self) -> Generator[Path, None, None]:
        with tempfile.TemporaryDirectory(prefix="_middeploy_configs_") as tempdir:
            path = Path(tempdir)
            self._render_configs(path)
            yield Path(path)

    def _check_compose_configs(self, paths: Sequence[Path]) -> None:
        partial_configs = [yaml.safe_load(path.read_text()) for path in paths]

        # Note that this doesn't match `docker-compose`'s config merging in general,
        # but should be close enough except for lists.
        config: dict[str, Any] = {}  # `reduce(deep_merge, configs, {})`
        for partial_config in partial_configs:
            config = deep_merge(config, partial_config)

        errors: list[str] = []

        app_image = self._app_docker_image
        app_image_full = f"{app_image}:${{{self._app_version_var_name}}}"
        app_services = {
            name: cfg
            for name, cfg in config["services"].items()
            if cfg.get("image") and cfg["image"].startswith(app_image)
        }
        if not app_services:
            errors.append(f'Did not find any `image: "{app_image}:…"` services')

        mistagged_services = {
            name: cfg["image"] for name, cfg in app_services.items() if cfg["image"] != app_image_full
        }
        if mistagged_services:
            errors.append(f"Found project services with `image` != {app_image_full!r}: {mistagged_services!r}")

        env_file = f"$HOME/{self._conf_relpath}"
        misenved_services = {
            name: cfg["env_file"] for name, cfg in app_services.items() if cfg.get("env_file") != env_file
        }
        if misenved_services:
            errors.append(f"Found project services with `env_file` != {env_file!r}: {misenved_services!r}")

        if errors:
            configs_str = " ".join(f"-f {path}" for path in paths)
            errors_str = "\n".join(f"    {error}" for error in errors)
            raise ValueError(f"Error checking config for `docker-compose {configs_str}`:\n{errors_str}")

    def _check_project(self) -> None:
        """Ensure there are no obvious mistakes in the current project"""
        compose_main = Path("./docker-compose.yaml")
        compose_prod = Path("./deploy/docker-compose.prod.yaml")
        compose_staging = Path("./deploy/docker-compose.prod.yaml")
        caddy_config = Path("./deploy/Caddyfile")

        required_files = [compose_main, compose_prod, caddy_config]
        # TODO: if `staging` is mentioned, also require the `compose_staging`

        missing_files = [str(path) for path in required_files if not path.is_file()]
        if missing_files:
            raise ValueError(f"Missing required files: {missing_files!r}")

        self._check_compose_configs([compose_main, compose_prod])
        if compose_staging.is_file():
            self._check_compose_configs([compose_main, compose_prod, compose_staging])

    def _hostname_from_name_tag(self, instance: str) -> str:
        try:
            name_tag = self._ssh(instance, _INSTANCE_NAME_SH)
        except subprocess.CalledProcessError as exc:
            raise NameTagError("cmd error", exc)
        name_tag = name_tag.strip()
        if "\n" in name_tag:
            raise NameTagError("suspicious name_tag", name_tag)
        prj = self._prjname
        return f"{name_tag}.{prj}.midas-io.services"

    def _make_hostname(self, instance: str) -> str:
        hostname = instance.rsplit("@", 1)[-1]
        # Convert ec2 hostnames to something more readable.
        # e.g. "ec2-11-22-33-44.eu-central-1.compute.amazonaws.com"
        match = re.search(r"^ec2-([0-9-]+)\.(?:[^.]+).compute.amazonaws.com$", hostname)
        if not match:  # Not an expected ec2 hostname.
            return hostname
        prj = self._prjname
        addr = match.group(1)  # e.g. "11-22-33-44"
        return f"{prj}-{addr}.{prj}.midas-io.services"

    def _set_hostname(self, instance: str) -> None:
        try:
            hostname = self._hostname_from_name_tag(instance)
        except NameTagError:
            hostname = self._make_hostname(instance)
        extra_tpl_vars = {"target_hostname_sq": self._sq(hostname)}
        set_hostname_cmd = self._sh_tpl(_SET_HOSTNAME_TPL, extra_vars=extra_tpl_vars)
        self._ssh(instance, set_hostname_cmd, capture=False)

    def _pull_prod_config(self, instance: str, force_overwrite: bool = False) -> None:
        conf_relpath = self._conf_relpath
        prod_config_path = self._prod_config_path
        if prod_config_path.is_file() and not force_overwrite:
            raise ValueError(f"Already exists ({force_overwrite=!r}): {prod_config_path!r}")

        self._rsync_any(src=f"{instance}:{conf_relpath}", dst=str(prod_config_path), args=["--delete-after"])

    def _write_prod_config(self, instance: str, force_overwrite: bool = False) -> None:
        conf_relpath = self._conf_relpath

        prod_config_path = self._prod_config_path
        if not prod_config_path.is_file():
            raise ValueError(f"Initial setup requires prod config at {prod_config_path}")

        if not force_overwrite and self._ssh_check(instance, f"ls -l {self._sq(conf_relpath)}"):
            return

        self._rsync(instance, args=["--mkpath"], src=str(prod_config_path), dst=conf_relpath)  # `~/.config` file

    def _set_up_docker(self, instance: str, force: bool = False) -> None:
        if not force and self._ssh_check(instance, "docker ps"):
            return

        docker_token = self._get_docker_token()
        extra_tpl_vars = {
            "docker_username_sq": self._sq(self._conf_value("DOCKER_USERNAME") or "midasinvestments"),
            "docker_token_sq": self._sq(docker_token),
        }
        set_up_docker_cmd = self._sh_tpl(_SET_UP_DOCKER_TPL, extra_vars=extra_tpl_vars)
        self._ssh(instance, set_up_docker_cmd, capture=False)
        # After doing `usermod` (add group), need to re-login to be able to use docker.
        docker_auth_cmd = self._sh_tpl(_DOCKER_AUTH_TPL, extra_vars=extra_tpl_vars)
        self._ssh(instance, docker_auth_cmd, capture=False)

    def _set_up_netdata(self, instance: str, force: bool = False) -> None:
        if not force and self._ssh_check(instance, "ls /etc/netdata/netdata_python_custom_sender.py"):
            return

        extra_tpl_vars = {
            "nd_claim_rooms_sq": self._sq(self._pyproj["tool"]["deploy"]["netdata_claim_rooms"]),
            "nd_claim_token_sq": self._sq(self._pyproj["tool"]["deploy"]["netdata_claim_token"]),
        }

        set_up_netdata_cmd = self._sh_tpl(_SET_UP_NETDATA_TPL, extra_vars=extra_tpl_vars)
        with self._config_files() as conffiles_path:
            self._rsync(instance, src=str(conffiles_path) + "/", dst="/tmp/_netdata_config", args=["--delete-after"])
        self._ssh(instance, set_up_netdata_cmd, capture=False)

    def _set_up_stuff(self, instance: str) -> None:
        set_up_stuff_cmd = self._sh_tpl(_SET_UP_STUFF_TPL)
        self._ssh(instance, set_up_stuff_cmd, capture=False)

    def _initial_setup_finalize(self, instance: str) -> None:
        initial_setup_finalize_cmd = self._sh_tpl(_INITIAL_SETUP_FINALIZE_TPL)
        self._ssh(instance, initial_setup_finalize_cmd, capture=False)

    def _initial_setup_reset(self, instance: str) -> None:
        reset_cmd = self._sh_tpl(r"rm -rf {prjname_sq}.reset && mv {prjname_sq} {prjname_sq}.reset")
        self._ssh(instance, reset_cmd, capture=False)

    def _initial_setup(self, instance: str, force: bool = False, force_config: bool = False) -> None:
        self._log(f"Setting up INITIAL {instance=!r}")

        # Very much not idempotent, thus using a separate flag.
        self._write_prod_config(instance, force_overwrite=force_config)

        self._set_hostname(instance)
        self._set_up_docker(instance, force=force)
        self._set_up_netdata(instance, force=force)
        self._set_up_stuff(instance)
        self._initial_setup_finalize(instance)

    def _main_setup(self, instance: str) -> None:
        deploy_type = self.get_deploy_type()
        if deploy_type is None or deploy_type == "production":
            main_setup_cmd = self._sh_tpl(_MAIN_SETUP_PROD_TPL)
        else:
            assert deploy_type == "staging"
            main_setup_cmd = self._sh_tpl(_MAIN_SETUP_STAGING_TPL)

        # Files that are used directly and not through the docker images.
        # TODO: `--delete-excluded`.
        self._rsync(
            instance,
            args=[
                "--include=*/",
                "--include=*compose*.yaml",
                "--include=deploy/Caddyfile",
                "--exclude=*",
                "--prune-empty-dirs",
                "--delete-after",
            ],
        )
        self._ssh(instance, main_setup_cmd, capture=False)

    def _process_instance(self, instance: str, cmd: str | None = None) -> None:
        if cmd == "echo":
            sys.stdout.write(f"{instance}\n")
            return

        self._log(f"Setting up {instance=!r}")
        status = self._ssh(instance, self._sh_tpl(_STATUS_CHECK_TPL))
        if status not in ("ok", "none"):
            raise ValueError(f"Unexpected status check result {status!r}")

        if cmd is not None:
            cmd_force = True
            if cmd == "initial_setup":
                self._initial_setup(instance)
            elif cmd == "pull_prod_config":
                self._pull_prod_config(instance, force_overwrite=cmd_force)
            elif cmd == "write_prod_config":
                self._write_prod_config(instance, force_overwrite=cmd_force)
            elif cmd == "set_hostname":
                self._set_hostname(instance)
            elif cmd == "set_up_docker":
                self._set_up_docker(instance, force=cmd_force)
            elif cmd == "set_up_netdata":
                self._set_up_netdata(instance, force=cmd_force)
            elif cmd == "set_up_stuff":
                self._set_up_stuff(instance)
            elif cmd == "initial_setup_reset":
                self._initial_setup_finalize(instance)
            elif cmd == "initial_setup_finalize":
                self._initial_setup_finalize(instance)
            elif cmd == "main_setup":
                self._main_setup(instance)
            else:
                raise ValueError(f"Unknown {cmd=!r}")
            return

        if status == "none":
            self._initial_setup(instance)
        self._main_setup(instance)

    def _main_prepare(self, image_tag: str = "latest") -> None:
        self._sh_tpl_vars["prjname_sq"] = self._sq(self._prjname)
        self._sh_tpl_vars["vervar_spec"] = f"{self._app_version_var_name}={self._sq(image_tag)}"
        self._sh_tpl_vars["main_image_sq"] = self._sq(f"{self._app_docker_image}:{image_tag}")

    def get_instances(self, deploy_type: TDeployType | None = None) -> list[str]:
        instances: str | list[str] | None
        instances = self._conf_value("DEPLOY_TARGET_INSTANCES")

        if not instances:
            if deploy_type is None:
                deploy_type = self.get_deploy_type()
            if deploy_type == "production":
                instances = self._pyproj["tool"]["deploy"].get("production_instances")
            elif deploy_type == "staging":
                instances = self._pyproj["tool"]["deploy"].get("staging_instances")

        if not instances:
            instances = self._pyproj["tool"]["deploy"].get("instances")

        if not instances:
            raise ValueError(f"No instances defined for {deploy_type=!r}")

        return instances if isinstance(instances, list) else instances.split()

    def main(self) -> None:
        # TODO: some `click` cmd or something.
        try:
            image_tag = sys.argv[1]
        except IndexError:
            image_tag = self._request_value("Image version (tag)")

        cmd = None
        if len(sys.argv) > 2:
            cmd = sys.argv[2]

        self._check_project()
        if cmd == "check":
            # TODO: more extensive checks
            return

        self._main_prepare(image_tag=image_tag)
        instances = self.get_instances()

        for instance in instances:
            self._process_instance(instance, cmd=cmd)

    @classmethod
    def run_cli(cls) -> None:
        if "--help" in sys.argv:
            sys.stdout.write(HELP + "\n")
            return
        cls().main()


if __name__ == "__main__":
    DeployManager.run_cli()
