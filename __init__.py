"""
Fetches specific HOTP/TOTP token from Yubikey OATH module
"""
import json
import typing as t
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from os.path import splitext
from pathlib import Path
from threading import Lock, Thread

from ykman.device import list_all_devices, SmartCardConnection
from yubikit.oath import Code, Credential, OathSession
from ykman.settings import AppData as YkSettings

from albert import *

try:
    from albert import TriggerQuery as Query
except ImportError:
    pass

md_iid = "2.0"
md_version = "0.4"
md_name = "Yubikey OTP"
md_description = "Fetches specific HOTP/TOTP token from Yubikey OATH module"
md_license = "BSD-2-Clause"
md_url = "https://github.com/albertlauncher/python"
md_maintainers = "@GwynBleidD"
md_lib_dependencies = ["yubikey-manager"]

__triggers__ = "otp "

ICON_LOCATIONS = [
    Path.home() / ".local/share/com.yubico.authenticator/issuer_icons/",
    Path.home() / ".var/app/com.yubico.yubioath/data/authenticator/issuer_icons/",
    # Path.home() / "Library/Containers/com.yubico.yubioath/Data/Library/Application Support/com.yubico.yubioath/issuer_icons/",
]


class IconFinderProtocol(t.Protocol):
    def get_icon(self, issuer: str, name: str) -> Path | None:
        ...


class IconFinder(IconFinderProtocol):
    def __init__(self, config_json: str, location):
        self.icons = self.load_icons(config_json)
        self.location = location

    @staticmethod
    def load_icons(config_json: str):
        return [
            {
                **icon,
                "issuer": [issuer.upper() for issuer in icon["issuer"]],
            } for icon in json.loads(config_json)["icons"]
        ]

    def get_icon(self, issuer: str, name: str) -> Path | None:
        issuer_upper = issuer.upper()
        name_upper = name.upper()

        def match_icon(el):
            return issuer_upper in el["issuer"]

        icon_configs = list(filter(match_icon, self.icons))

        if not len(icon_configs):
            return None

        filename = icon_configs[0]["filename"]
        return self.location / (sha256(filename.encode()).hexdigest()[:32] + splitext(filename)[1])


class NullIconFinder(IconFinderProtocol):
    def get_icon(self, issuer: str, name: str) -> None:
        return None


def icon_finder() -> IconFinderProtocol:
    for location in ICON_LOCATIONS:
        if not location.exists():
            continue
        config_file = location / "50fe9d7f9b390282339fb6264d30773b.json"
        if not config_file.exists():
            continue

        try:
            with config_file.open() as fd:
                return IconFinder(fd.read(), location)
        except Exception:
            continue
    return NullIconFinder()


class Mode(str, Enum):
    FIRST = "first", "use only first detected Yubikey"
    ALL = "all", "use all entries from all yubikeys"
    MERGE_OPEN = (
        "merge by name and code",
        "use all entries, but try to merge identical ones by name and generated code (don't merge requiring touch)",
    )
    MERGE_ALL = "merge by name", "use all entries, but try to merge identical ones by name (also merge requiring touch)"

    def __new__(cls, value, description):
        obj = str.__new__(cls, [value])
        obj._value_ = value
        obj.description = description
        return obj


@dataclass
class Config:
    fallback_mode: Mode
    preferred_devices: t.Sequence[int] = ()


class Plugin(PluginInstance, TriggerQueryHandler):
    config: Config

    @property
    def multi_device_mode(self) -> str:
        return self.config.fallback_mode.value

    @multi_device_mode.setter
    def multi_device_mode(self, value: str):
        self.config.fallback_mode = self.prepare_multi_device_mode(value)
        self.writeConfig('multi_device_mode', value)

    @property
    def preferred_devices(self) -> str:
        return ",".join(self.config.preferred_devices)

    @preferred_devices.setter
    def preferred_devices(self, value: str):
        self.config.preferred_devices = self.prepare_preferred_devices(value)
        self.writeConfig('preferred_devices', value)

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

        self.config = self.prepare_config()
        self.notification = None

    def configWidget(self):
        return [
            {
                'type': "label",
                'text': __doc__.strip(),
            },
            {
                'type': "combobox",
                'property': "multi_device_mode",
                'label': "Multi Device Mode",
                'items': [mode.value for mode in Mode],
                'widget_properties': {'tooltip': 'How plugin should behave when multiple yubikeys are detected'}
            },
            {
                'type': "label",
                'text': "\n".join(
                    f"{mode.value} — {mode.description}" for mode in Mode
                ),
            },
        ]

    def get_unlocked_yk_session(self, connection, yk_settings):
        session = OathSession(connection)

        if session.locked:
            # TODO: maybe some logic when preferred device is password locked and password is not
            #  saved with ykman?
            keys = yk_settings
            if session.device_id in keys:
                try:
                    session.validate(bytes.fromhex(keys.get_secret(session.device_id)))
                except Exception:
                    return None
            else:
                return None
        return session

    def clip_action_factory(self, entry: Credential, code: Code | None, device_serial: int, type_in: bool = False):
        if type_in:
            clipboard_method = setClipboardTextAndPaste
        else:
            clipboard_method = setClipboardText

        def clip_action_notouch():
            clipboard_method(code.value)

        def clip_action_touch():
            devs = list_all_devices()
            self.notification = Notification(
                title="Touch your yubikey",
                text=f"You need to touch your yubikey to generate TOTP code for {entry.issuer} ({entry.name})",
            )
            for dev, nfo in devs:
                if nfo.serial == device_serial:
                    with dev.open_connection(SmartCardConnection) as conn:
                        session = self.get_unlocked_yk_session(conn, yk_settings=YkSettings('oath_keys'))
                        code = session.calculate_code(entry)
                    clipboard_method(code.value)
                    break
            self.notification = None

        if code:
            return clip_action_notouch
        else:
            return Thread(target=clip_action_touch).start

    @staticmethod
    def prepare_multi_device_mode(val: str) -> Mode:
        try:
            return Mode(val or Mode.ALL.value)
        except ValueError:
            return Mode.ALL

    @staticmethod
    def prepare_preferred_devices(val: str) -> tuple[int]:
        return ()
        # return tuple(map(int, (self.readConfig("preferred_devices", str) or "").split(',')))

    def prepare_config(self):
        return Config(
            fallback_mode=self.prepare_multi_device_mode(self.readConfig("multi_device_mode", str)),
            preferred_devices=self.prepare_preferred_devices(self.readConfig("preferred_devices", str)),
        )

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

        creds = {}
        yk_settings = YkSettings('oath_keys')

        if mode == Mode.MERGE_ALL:
            key = lambda entry: (entry[0].id, entry[1].value if entry[1] else None)
        elif mode == Mode.MERGE_OPEN:
            key = lambda entry: (entry[0].id, entry[1].value if entry[1] else entry[2])
        else:
            key = lambda entry: (entry[0].id, entry[1].value if entry[1] else None, entry[2])

        for device, dev_info in devices:
            with device.open_connection(SmartCardConnection) as conn:
                session = self.get_unlocked_yk_session(conn, yk_settings=yk_settings)

                if session is None:
                    continue

                creds = {
                    key(
                        entry := (
                            cred,
                            code,
                            dev_info.serial
                        )
                    ): entry for cred, code in session.calculate_all().items()
                } | creds
            if mode == Mode.FIRST:
                break

        cache_for = min([
            code.valid_to for _, code, _ in creds.values()
            if code is not None
        ] + [float('inf')])
        cache_for = 30 if cache_for == float('inf') else cache_for
        self.creds_cache['expiration'] = cache_for
        self.creds_cache['data'] = creds.values()

        return creds.values()

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

    def handleTriggerQuery(self, query: Query):
        stripped = query.string.strip()
        icons = icon_finder()
        if stripped:
            for entry, code, device_serial in self.get_credentials(stripped):
                query.add(
                    StandardItem(
                        id=f'otp-{entry.id.decode()}',
                        iconUrls=list(
                            filter(None, [str(icons.get_icon(entry.issuer, entry.name))]),
                        ),
                        text=self.format_value(code) if code else '*** ***',
                        subtext=f'{entry.issuer} ({entry.name}) {entry.id}',
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
