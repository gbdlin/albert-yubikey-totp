# -*- coding: utf-8 -*-
"""
Fetch specific HOTP/TOTP token from Yubikey OATH module
"""
import re
from dataclasses import field, InitVar
from pydantic.dataclasses import dataclass
from functools import reduce
from operator import or_
from pathlib import Path
from typing import Sequence, Union, Pattern

import toml
from pyperclip import copy
from ykman.oath import OathController
from ykman.descriptor import get_descriptors
from ykman.util import TRANSPORT

try:
    from albert import *
except ImportError:
    from albert_mock import *

__title__ = "Yubikey OTP"
__version__ = "0.4.0"
__triggers__ = "otp "
__authors__ = ["GwynBleidD"]
__py_deps__ = ['yubikey-manager', 'pyperclip', 'toml']

CONFIG_PATH = (configLocation() / Path('yubiotp_config.toml')).expanduser().resolve()

RE_FLAGS = {
    "a": re.ASCII,
    "i": re.IGNORECASE,
    "L": re.LOCALE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "x": re.VERBOSE,
}


def re_flags(flags_str: str):
    return reduce(or_, (
        RE_FLAGS[flag]
        for flag in flags_str
    ))


@dataclass
class IconMatch:
    name: str
    icon: Path
    match: Pattern
    match_flags: InitVar[str] = ''

    def __post_init__(self, match_flags):
        self.match = re.compile(self.match, re_flags(match_flags))


@dataclass
class IconsConfig:
    default: Union[str, Path] = ''
    mapping: Sequence[IconMatch] = field(default_factory=list)


@dataclass
class Config:
    icons: IconsConfig


def clip_action_factory(entry, controller):
    def clip_action():
        code = controller.calculate(entry)
        copy(code.value)

    return clip_action


def prepare_config():
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as fd:
            config = toml.load(fd)
            print(config)
            return Config(**config)
    else:
        return {}

    data_path = str(Path(dataLocation()).expanduser().resolve())

    return Config(
        icons=IconsConfig(
            default=config.get('icons', {}).get('default', ''),
            mapping=[
                IconMatch(
                    name=match['name'],
                    match=re.compile(
                        pattern=match['match'],
                        flags=re_flags(match.get('match_flags', '')),
                    ),
                    icon=icon
                )
                for match in config.get('icons', {}).get('mapping', [])
                if (icon := Path(match['icon'].format(
                    DATA=data_path,
                ))).exists()
            ],
        ),
    )


def match_icon(entry, config: Config):
    match_name = f'{entry.issuer} ({entry.name})'

    for match in config.icons.mapping:
        if match.match.search(match_name) is None:
            continue
        return str(match.icon)

    return config.icons.default


def handleQuery(query):
    config = prepare_config()

    if query.isTriggered:
        descriptors = get_descriptors()
        if not len(descriptors):
            return []

        descriptor = descriptors[0]
        if not descriptor.mode.transports & TRANSPORT.CCID:
            return []

        device = descriptor.open_device(TRANSPORT.CCID)
        controller = OathController(device.driver)

        creds = [cr for cr, c in controller.calculate_all()]
        if query.string:
            creds = [
                entry for entry in creds if query.string.lower() in entry.printable_key.lower()
            ]

        return [
            Item(
                id=f'otp-{entry.printable_key}',
                icon=match_icon(entry, config),
                text='*** ***' if entry.touch else controller.calculate(entry).value,
                subtext=f'{entry.issuer} ({entry.name})',
                completion=f'{__triggers__}{entry.printable_key}',
                actions=[
                    FuncAction(
                        f"Copy token to clipboard",
                        clip_action_factory(entry, controller)
                    ),
                ] + ([] if entry.touch else [
                    ProcAction(
                        text="Type in token",
                        commandline=["xdotool", "type", '--clearmodifiers', (controller.calculate(entry).value)]
                    ),
                ])
            )
            for entry in creds
        ]


if __name__ == "__main__":
    print(CONFIG_PATH)
    print(prepare_config())
