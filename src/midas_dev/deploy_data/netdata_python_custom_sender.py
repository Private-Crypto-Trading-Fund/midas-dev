#!/usr/bin/env python3

# https://learn.netdata.cloud/docs/agent/health/notifications/custom
import sys
import time
from typing import Any

import requests

PROJECT = "___PRJNAME___"
ENDPOINT = "___ENDPOINT___"
RETRIES = 50
ARGS_INFO: tuple[tuple[str, str], ...] = (
    ("host", "the host generated this event"),
    ("url_host", "same as ${host} but URL encoded"),  # noqa: FS003
    ("unique_id", "the unique id of this event"),
    ("alarm_id", "the unique id of the alarm that generated this event"),
    ("event_id", "the incremental id of the event, for this alarm id"),
    ("when", "the timestamp this event occurred"),
    ("name", "the name of the alarm, as given in netdata health.d entries"),
    ("url_name", "same as ${name} but URL encoded"),  # noqa: FS003
    ("chart", "the name of the chart (type.id)"),
    ("url_chart", "same as ${chart} but URL encoded"),  # noqa: FS003
    ("family", "the family of the chart"),
    ("url_family", "same as ${family} but URL encoded"),  # noqa: FS003
    (
        "status",
        "the current status: REMOVED, UNINITIALIZED, UNDEFINED, CLEAR, WARNING, CRITICAL",
    ),
    (
        "old_status",
        "the previous status: REMOVED, UNINITIALIZED, UNDEFINED, CLEAR, WARNING, CRITICAL",
    ),
    ("value", "the current value of the alarm"),
    ("old_value", "the previous value of the alarm"),
    ("src", "the line number and file the alarm has been configured"),
    ("duration", "the duration in seconds of the previous alarm state"),
    ("duration_txt", "same as ${duration} for humans"),  # noqa: FS003
    ("non_clear_duration", "the total duration in seconds this is/was non-clear"),
    (
        "non_clear_duration_txt",
        "same as ${non_clear_duration} for humans",  # noqa: FS003
    ),
    ("units", "the units of the value"),
    ("info", "a short description of the alarm"),
    ("value_string", "friendly value (with units)"),
    ("old_value_string", "friendly old value (with units)"),
    ("image", "the URL of an image to represent the status of the alarm"),
    ("color", "a color in #AABBCC format for the alarm"),
    ("goto_url", "the URL the user can click to see the netdata dashboard"),
    ("calc_expression", "the expression evaluated to provide the value for the alarm"),
    ("calc_param_values", "the value of the variables in the evaluated expression"),
    ("total_warnings", "the total number of alarms in WARNING state on the host"),
    ("total_critical", "the total number of alarms in CRITICAL state on the host"),
    # these are more human friendly:
    ("alarm", 'like "name = value units"'),
    ("status_message", 'like "needs attention", "recovered", "is critical"'),
    ("severity", 'like "Escalated to CRITICAL", "Recovered from WARNING"'),
    ("raised_for", 'like "(alarm was raised for 10 minutes)"'),
)

EMOJI_MAP = {
    "WARNING": "⚠️",
    "CRITICAL": "🔴",
    "CLEAR": "✅",
    None: "⚪",
}

MESSAGE_TEMPLATE = r"""
{emoji} {host} {status_message} - <b>{name}</b>
{chart} ({family})
<a href="{goto_url}">{alarm}</a>
<i>{info}</i>
"""


class Sender:
    project_name: str = PROJECT
    tries: int = RETRIES  # total number of attempts.
    endpoint: str = ENDPOINT
    args_info: tuple[tuple[str, str], ...] = ARGS_INFO
    message_template: str = MESSAGE_TEMPLATE
    emoji_map: dict[str | None, str] = EMOJI_MAP

    def parse_args(self, args_list: list[str]) -> dict[str, str | None]:
        data: dict[str, str | None] = {}
        for arg in args_list:
            pieces = arg.split("=", 1)
            if len(pieces) != 2:
                raise ValueError(f"Malformed {arg=!r}")
            key, val = pieces
            data[key] = val

        for arg_name, _ in self.args_info:
            data.setdefault(arg_name, None)

        return data

    def send_data_inner(self, body_data: dict[str, Any]) -> None:
        resp = requests.post(
            url=self.endpoint,
            json=body_data,
            stream=True,
        )
        resp.raise_for_status()
        resp.close()

    def send_data(self, body_data: dict[str, Any]) -> None:
        for retries_remain in range(self.tries - 1, -1, -1):
            try:
                self.send_data_inner(body_data)
            except Exception:
                if not retries_remain:
                    raise
                time.sleep(5)

    def main_inner(self, args_list: list[str]) -> None:
        assert args_list
        data = self.parse_args(args_list)
        emoji = self.emoji_map.get(data["status"]) or self.emoji_map[None]
        message = self.message_template.format(emoji=emoji, **data)
        body_data = {"text": message, "level": data["status"], "project": self.project_name}
        self.send_data(body_data)

    @classmethod
    def main(cls):
        try:
            cls().main_inner(sys.argv[1:])
            sys.stdout.write("ok\n")
            sys.stdout.flush()
        except Exception as exc:
            sys.stdout.write(repr(exc))
            sys.stdout.flush()


if __name__ == "__main__":
    Sender.main()
