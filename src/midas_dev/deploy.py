#!/usr/bin/env python3
import contextlib
import functools
import os
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Generator, Iterable
from pathlib import Path
from typing import Any, TypeVar

import toml

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

Introduction to a new project:

  * Configure `pyproject.toml` `[tool.deploy]`:
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
  * Configure own environment:
    * Docker token into `~/.config/midas/docker_token`
    * Produciton config into `~/.config/midas/${project_name}/.env`
  * Test the deployment on a temporary aws host.

"""


HERE = Path(__file__).parent
CONFIGS_PATH = HERE / "deploy_data"
DOCKER_TOKEN_PATH = Path.home() / ".config/midas/docker_token"
_STATUS_CHECK_TPL = r"""
set -eux
if [ -d {prjname_sq} ]; then
    echo ok
else
    echo none
fi
"""
_INITIAL_SETUP_TPL = r"""
set -eux
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical
export NEEDRESTART_MODE=a
export {vervar_spec}

sudo hostnamectl set-hostname {target_hostname_sq}

sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install docker.io docker-compose python3-pip python3-requests -y
sudo snap remove amazon-ssm-agent --purge

sudo groupadd -f docker
sudo usermod -aG docker "$(whoami)"
sudo chmod 666 /var/run/docker.sock

sudo systemctl enable docker.service
sudo systemctl enable containerd.service
sudo systemctl daemon-reload
sudo systemctl restart docker

echo {docker_token_sq} | docker login --username {docker_username_sq} --password-stdin

curl -Ss https://my-netdata.io/kickstart.sh > /tmp/netdata-kickstart.sh
sh -x /tmp/netdata-kickstart.sh \
    --claim-rooms {nd_claim_rooms_sq} \
    --claim-token {nd_claim_token_sq} \
    --claim-url https://app.netdata.cloud

sudo cp /tmp/_netdata_config/* /etc/netdata/
sudo systemctl restart netdata.service
mkdir -p {prjname_sq}
"""
_MAIN_SETUP_TPL = r"""
set -eux
export LC_ALL=C
export {vervar_spec}

cd {prjname_sq}
docker pull {main_image_sq}
docker-compose -f docker-compose.yaml -f deploy/docker-compose.prod.yaml pull --include-deps
docker-compose -f docker-compose.yaml -f deploy/docker-compose.prod.yaml down
docker-compose -f docker-compose.yaml -f deploy/docker-compose.prod.yaml up --no-build --detach

sleep 10
docker ps
"""

TType = TypeVar("TType")


def ensure_type(value: Any, type_: type[TType]) -> TType:
    """`cast(value, type_)` with runtime `isinstance` validation"""
    if not isinstance(value, type_):
        raise ValueError("Unexpected value type", dict(type_=type_, value=value))
    return value


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
    def _ssh_options(self) -> str:
        return (
            self._conf_value("DEPLOY_SSH_OPTIONS")
            or self._pyproj["tool"]["deploy"].get("ssh_options")
            or "-p 22022 -l ubuntu"
        )

    def _log(self, message: str) -> None:
        sys.stderr.write(f"+ {message}\n")

    def _sh(self, cmd: str, capture: bool = True, check: bool = True, **kwargs: Any) -> str:
        self._log(f"$ {cmd}")
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE if capture else None, check=check, **kwargs)
        return (res.stdout or b"").decode(errors="replace").rstrip("\n")

    def _ssh(self, instance: str, cmd: str, capture: bool = True) -> str:
        return self._sh(f"ssh  {self._ssh_options}  {self._sq(instance)}  {self._sq(cmd)}", capture=capture)

    def _rsync(
        self, instance: str, src: str = ".", dst: str | None = None, args: Iterable[str] = (), **kwargs: Any
    ) -> None:
        if not dst:
            dst = f"{self._prjname}/"
        cmd_pieces = [
            "rsync",
            f"--rsh=ssh {self._ssh_options}",
            "--verbose",
            "--recursive",
            *args,
            src,
            f"{instance}:{dst}",
        ]
        cmd = self._sh_join(cmd_pieces)
        self._sh(cmd, capture=False, **kwargs)

    def _sh_tpl(self, tpl: str, extra_vars: dict[str, str] | None = None) -> str:
        return tpl.format(**self._sh_tpl_vars, **(extra_vars or {}))

    def _render_configs(self, path: Path) -> None:
        filenames = ["netdata_python_custom_sender.py", "health_alarm_notify.conf"]
        tpl_replacements = {
            "___PRJNAME___": self._prjname,
            "___ENDPOINT___": self._pyproj["tool"]["deploy"]["netdata_sender_endpoint"],
        }
        for filename in filenames:
            src = CONFIGS_PATH / filename
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

    def _initial_setup(self, instance: str) -> None:
        self._log(f"Setting up INITIAL {instance=!r}")

        conf_relpath = f".config/midas/{self._prjname}/.env"
        prod_config_path = Path.home() / f"{conf_relpath}.prod"  # e.g. `~/.config/midas/someproj/.env.prod`
        if not prod_config_path.is_file():
            raise ValueError(f"Initial setup requires prod config at {prod_config_path}")

        docker_token = self._get_docker_token()

        extra_tpl_vars = {
            "target_hostname_sq": self._sq(instance.rsplit("@", 1)[-1]),  # strip username just in case,
            "docker_username_sq": self._sq(self._conf_value("DOCKER_USERNAME") or "midasinvestments"),
            "docker_token_sq": self._sq(docker_token),
            "nd_claim_rooms_sq": self._sq(self._pyproj["tool"]["deploy"]["netdata_claim_rooms"]),
            "nd_claim_token_sq": self._sq(self._pyproj["tool"]["deploy"]["netdata_claim_token"]),
        }
        initial_setup_cmd = self._sh_tpl(_INITIAL_SETUP_TPL, extra_vars=extra_tpl_vars)

        self._rsync(instance, args=["--mkpath"], src=str(prod_config_path), dst=conf_relpath)  # `~/.config` file
        with self._config_files() as conffiles_path:
            self._rsync(instance, src=str(conffiles_path) + "/", dst="/tmp/_netdata_config")
        self._ssh(instance, initial_setup_cmd, capture=False)

    def _main_setup(self, instance: str) -> None:
        main_setup_cmd = self._sh_tpl(_MAIN_SETUP_TPL)

        # Files that are used directly and not through the docker images.
        # TODO: `--delete-excluded`.
        self._rsync(
            instance,
            args=[
                "--include=*/",
                "--include=*compose*.y*ml",
                "--include=deploy/Caddyfile",
                "--include=deploy/netdata/*",
                "--exclude=*",
                "--prune-empty-dirs",
            ],
        )
        self._ssh(instance, main_setup_cmd, capture=False)

    def _process_instance(self, instance: str) -> None:
        self._log(f"Setting up {instance=!r}")
        status = self._ssh(instance, self._sh_tpl(_STATUS_CHECK_TPL))
        if status not in ("ok", "none"):
            raise ValueError(f"Unexpected status check result {status!r}")
        if status == "none":
            self._initial_setup(instance)
        self._main_setup(instance)

    def main(self) -> None:
        try:
            image_tag = sys.argv[1]
        except IndexError:
            image_tag = self._request_value("Image version (tag)")

        instances = self._conf_value("DEPLOY_TARGET_INSTANCES") or self._pyproj["tool"]["deploy"]["instances"]
        vervar = f"{self._prjname.upper()}_IMAGE_VERSION"  # e.g. SOMEPROJ_IMAGE_VERSION
        self._sh_tpl_vars["prjname_sq"] = self._sq(self._prjname)
        self._sh_tpl_vars["vervar_spec"] = f"{vervar}={self._sq(image_tag)}"
        self._sh_tpl_vars["main_image_sq"] = self._sq(f"investmentsteam/{self._prjname}:{image_tag}")

        for instance in instances.split():
            self._process_instance(instance)

    @classmethod
    def run_cli(cls) -> None:
        if "--help" in sys.argv:
            sys.stdout.write(HELP + "\n")
            return
        cls().main()


if __name__ == "__main__":
    DeployManager.run_cli()
