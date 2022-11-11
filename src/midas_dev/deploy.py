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
from typing import Any

import toml

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

sudo curl https://my-netdata.io/kickstart.sh > /tmp/netdata-kickstart.sh
sh /tmp/netdata-kickstart.sh \
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
docker-compose -f docker-compose.yml -f deploy/docker-compose.prod.yml pull --include-deps
docker-compose -f docker-compose.yml -f deploy/docker-compose.prod.yml down
docker-compose -f docker-compose.yml -f deploy/docker-compose.prod.yml up --no-build --detach

sleep 10
docker ps
"""


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
        return self._pyproj["tool"]["poetry"]["name"]

    def _log(self, message: str) -> None:
        sys.stderr.write(f"+ {message}\n")

    def _sh(self, cmd: str, capture: bool = True, check: bool = True, **kwargs: Any) -> str:
        self._log(f"$ {cmd}")
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE if capture else None, check=check, **kwargs)
        return (res.stdout or b"").decode(errors="replace").rstrip("\n")

    def _ssh(self, instance: str, cmd: str) -> str:
        return self._sh(f"ssh {self._sq(instance)} {self._sq(cmd)}")

    def _rsync(self, instance, src: str = ".", dst: str | None = None, args: Iterable[str] = (), **kwargs: Any) -> None:
        if not dst:
            dst = f"{self._prjname}/"
        cmd_pieces = ["rsync", "--verbose", "--recursive", *args, src, f"{instance}:{dst}"]
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
        self._ssh(instance, initial_setup_cmd)

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
        self._ssh(instance, main_setup_cmd)

    def _process_instance(self, instance: str) -> None:
        self._log(f"Setting up {instance=!r}")
        status = self._ssh(instance, self._sh_tpl(_STATUS_CHECK_TPL))
        if status not in ("ok", "none"):
            raise ValueError(f"Unexpected status check result {status!r}")
        if status == "none":
            self._initial_setup(instance)
        self._main_setup(instance)

    def main(self):
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
        cls().main()


if __name__ == "__main__":
    DeployManager.run_cli()
