# -*- coding: utf-8 -*-
"""
Fetches specific HOTP/TOTP token from Yubikey OATH module
"""
import os
import re
import typing as t
try:
    import tomllib
except ImportError:
    import toml as tomllib

os.environ['YKMAN_XDG_EXPERIMENTAL'] = "1"

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import reduce
from operator import or_
from pathlib import Path
from threading import Lock

from ykman.device import list_all_devices, SmartCardConnection
from yubikit.oath import Code, Credential, OathSession
from ykman.settings import AppData as YkSettings

from albert import *

md_iid = "2.0"
md_version = "0.4"
md_name = "Yubikey OTP"
md_description = "Fetches specific HOTP/TOTP token from Yubikey OATH module"
md_license = "BSD-2-Clause"
md_url = "https://github.com/albertlauncher/python"
md_maintainers = "@GwynBleidD"
md_lib_dependencies = ["yubikey-manager", "toml"]

__triggers__ = "otp "

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
    mapping: t.Sequence[IconMatch]


@dataclass
class Config:
    fallback_mode: Mode
    icons: IconsConfig
    preferred_devices: t.Sequence[int] = ()


class Plugin(PluginInstance, TriggerQueryHandler):
    config: Config

    def __init__(self):
        TriggerQueryHandler.__init__(self,
                                     id=md_id,
                                     name=md_name,
                                     description=md_description,
                                     synopsis="service_name",
                                     defaultTrigger='otp ')
        PluginInstance.__init__(self, extensions=[self])
        super().__init__()
        self.creds_cache = {}
        self.get_creds_lock = Lock()

        self.config_path = self.configLocation / "yubiotp_config.toml"

        self.config = self.prepare_config()

    def get_unlocked_yk_session(self, connection, yk_settings):
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

    def clip_action_factory(self, entry: Credential, code: t.Optional[Code], device_serial: int, type_in: bool = False):
        if type_in:
            clipboard_method = setClipboardTextAndPaste
        else:
            clipboard_method = setClipboardText

        def clip_action_notouch():
            clipboard_method(code.value)

        def clip_action_touch():
            devs = list_all_devices()
            for dev, nfo in devs:
                if nfo.serial == device_serial:
                    with dev.open_connection(SmartCardConnection) as conn:
                        session = self.get_unlocked_yk_session(conn, yk_settings=YkSettings('oath'))
                        code = session.calculate_code(entry)
                    clipboard_method(code.value)

        if code:
            return clip_action_notouch
        else:
            return clip_action_touch

    def prepare_config(self):
        if self.config_path.exists():
            with self.config_path.open() as fd:
                config = tomllib.load(fd)
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
                        DATA=self.dataLocation,
                    ))).exists()
                ],
            ),
        )

    def match_icon(self, entry):
        match_name = f'{entry.issuer} ({entry.name})'

        for match in self.config.icons.mapping:
            if match.match.search(match_name) is None:
                continue
            return str(match.icon)

        return self.config.icons.default

    def order_devices(self, devices, order):
        def order_fn(device):
            return (order.index(device[1].serial) if device[1].serial in order else float('inf')), device[1].serial

        return list(sorted(devices, key=order_fn))

    def get_all_credentials(self):
        if self.creds_cache.get('expiration', 0) > datetime.now().timestamp():
            return self.creds_cache.get('data')

        devices = list_all_devices()
        devices = self.order_devices(devices, self.config.preferred_devices)

        if set(self.config.preferred_devices) & {dev_info.serial for _, dev_info in devices}:
            mode = Mode.FIRST
        else:
            mode = self.config.fallback_mode

        creds = []
        yk_settings = YkSettings('oath')

        for i, (device, dev_info) in enumerate(devices):
            if i > 0 and mode == Mode.FIRST:
                break
            with device.open_connection(SmartCardConnection) as conn:
                session = self.get_unlocked_yk_session(conn, yk_settings=yk_settings)

                if session is None:
                    continue

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
        self.creds_cache['expiration'] = cache_for
        self.creds_cache['data'] = creds

        return creds

    def get_credentials(self, query):
        self.get_creds_lock.acquire()
        creds = self.get_all_credentials()
        self.get_creds_lock.release()
        yield from (
            (entry, code, device_serial)
            for entry, code, device_serial in creds
            if query.lower() in entry.id.decode().lower()
        )

    def format_value(self, code):
        return code.value

    def handleTriggerQuery(self, query: TriggerQuery):
        stripped = query.string.strip()
        if stripped:
            for entry, code, device_serial in self.get_credentials(stripped):
                print(device_serial)
                query.add(
                    StandardItem(
                        id=f'otp-{entry.id.decode()}',
                        # iconUrls=self.match_icon(entry),
                        text=self.format_value(code) if code else '*** ***',
                        subtext=f'{entry.issuer} ({entry.name})',
                        actions=[
                            Action(
                                id=f'otp-{entry.id.decode()}-clip',
                                text=f"Copy to clipboard",
                                callable=self.clip_action_factory(entry, code, device_serial),
                            ),
                            Action(
                                id=f'otp-{entry.id.decode()}-clip-and-paste',
                                text="Copy to clipboard and type",
                                callable=self.clip_action_factory(entry, code, device_serial, True),
                            ),
                        ],
                    ),
                )
