# -*- coding: utf-8 -*-
"""
Fetch specific HOTP/TOTP token from Yubikey OATH module
"""
import os
import re
import typing as t

os.environ['YKMAN_XDG_EXPERIMENTAL'] = "1"

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import reduce
from operator import or_
from pathlib import Path
from threading import Lock

import toml
from pyperclip import copy
from ykman.device import connect_to_device, list_all_devices, SmartCardConnection
from yubikit.oath import Code, Credential, OathSession
from ykman.settings import AppData as YkSettings

from albert import *

__title__ = "Yubikey OTP"
__version__ = "0.4.0"
__triggers__ = "otp "
__authors__ = ["GwynBleidD"]
__py_deps__ = ['yubikey-manager', 'pyperclip', 'toml']

CONFIG_PATH = configLocation() / Path('yubiotp_config.toml')

RE_FLAGS = {
    "a": re.ASCII,
    "i": re.IGNORECASE,
    "L": re.LOCALE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "x": re.VERBOSE,
}


class Mode(Enum):
    FIRST = 'first'            # use only first detected Yubikey
    ALL = 'all'                # use all entries from all yubikeys
    MERGE_OPEN = 'merge_open'  # use all entries, but try to display identical only once (skip ones requiring touch)
    MERGE_ALL = 'merge_all'    # use all entries, but try to display identical only once (include ones requiring touch)


def re_flags(flags_str: str):
    return reduce(or_, (
        RE_FLAGS[flag]
        for flag in flags_str
    ))


@dataclass
class IconMatch:
    name: str
    match: re.Pattern
    icon: Path


@dataclass
class IconsConfig:
    default: t.Union[str, Path]
    mapping: Sequence[IconMatch]


@dataclass
class Config:
    fallback_mode: Mode
    icons: IconsConfig
    preferred_devices: Sequence[int] = ()


def get_unlocked_yk_session(connection, yk_settings):
    session = OathSession(connection)

    if session.locked:
        # TODO: maybe some logic when preferred device is password locked and password is not
        #  saved with ykman?
        keys = yk_settings.setdefault('keys', {})
        if session.device_id in keys:
            try:
                session.validate(bytes.fromhex(keys[session.device_id]))
            except Exception:
                return None
        else:
            return None
    return session


def clip_action_factory(entry: Credential, code: t.Optional[Code], device_serial: int):
    def clip_action_notouch():
        copy(code.value)

    def clip_action_touch():
        with connect_to_device(device_serial, [SmartCardConnection])[0] as conn:
            session = get_unlocked_yk_session(conn, yk_settings=YkSettings('oath'))
            code = session.calculate_code(entry)
        copy(code.value)

    if code:
        return clip_action_notouch
    else:
        return clip_action_touch


def prepare_config():
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as fd:
            config = toml.load(fd)
    else:
        config = {}

    return Config(
        fallback_mode=config.get('fallback_mode', Mode.ALL),
        preferred_devices=config.get('preferred_devices', ()),
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
                    DATA=dataLocation(),
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


def order_devices(devices, order):
    def order_fn(device):
        return (order.index(device[1].serial) if device[1].serial in order else float('inf')), device[1].serial

    return list(sorted(devices, key=order_fn))


creds_cache = {}
get_creds_lock = Lock()


def get_all_credentials(config):
    if creds_cache.get('expiration', 0) > datetime.now().timestamp():
        return creds_cache.get('data')

    devices = list_all_devices()
    devices = order_devices(devices, config.preferred_devices)

    if set(config.preferred_devices) & {dev_info.serial for _, dev_info in devices}:
        mode = Mode.FIRST
    else:
        mode = config.fallback_mode

    creds = []
    yk_settings = YkSettings('oath')

    for i, (device, dev_info) in enumerate(devices):
        if i > 0 and mode == Mode.FIRST:
            break
        with device.open_connection(SmartCardConnection) as conn:
            session = get_unlocked_yk_session(conn, yk_settings=yk_settings)

            creds += [
                (
                    cred, 
                    None if cred.touch_required else session.calculate_code(cred), 
                    dev_info.serial
                ) for cred in session.calculate_all()
            ]
    if mode == Mode.MERGE_OPEN:
        ...  # TODO: implement merging logic
    if mode == Mode.MERGE_ALL:
        ...  # TODO: implement merging logic

    cache_for = min([
        code.valid_to for _, code, _ in creds
        if code is not None
    ] + [float('inf')])
    cache_for = 30 if cache_for == float('inf') else cache_for
    creds_cache['expiration'] = cache_for
    creds_cache['data'] = creds

    return creds


def get_credentials(query, config):
    get_creds_lock.acquire()
    creds = get_all_credentials(config)
    get_creds_lock.release()
    yield from (
        (entry, code, device_serial)
        for entry, code, device_serial in creds
        if query.lower() in entry.id.decode().lower()
    )

def format_value(code):
    return code.value


def handleQuery(query):
    config = prepare_config()

    if query.isTriggered:
        return [
            Item(
                id=f'otp-{entry.id.decode()}',
                icon=match_icon(entry, config),
                text=format_value(code) if code else '*** ***',
                subtext=f'{entry.issuer} ({entry.name})',
                completion=f'{__triggers__}{entry.id.decode()}',
                actions=[
                    FuncAction(
                        f"Copy token to clipboard",
                        clip_action_factory(entry, code, device_serial)
                    ),
                ] + ([
                    ProcAction(
                        text="Type in token",
                        commandline=["xdotool", "type", '--clearmodifiers', code.value]
                    ),
                ] if code else [])
            )
            for entry, code, device_serial in get_credentials(query.string, config)
        ]
