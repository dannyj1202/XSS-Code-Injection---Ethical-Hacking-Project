"""YAML-backed settings for the injection tool.

The schema mirrors the ``config.yaml`` example documented in the project
README (``injection``, ``beef``, ``network``, ``logging``, ``stats`` plus a
few top-level keys). All fields have safe defaults so the tool runs without
a config file at all; a file, if given, only overrides specific keys.
"""

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class _GettableMixin:
    """Adds dict-style ``.get()`` to a dataclass.

    ``cli.py`` builds injector configs with calls like
    ``config.get('beef', {}).get('host', ...)`` against the nested config
    object. That reads naturally for a plain nested dict, so this mixin
    makes each settings dataclass answer to the same call shape.
    """

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class InjectionConfig(_GettableMixin):
    """Controls what gets injected, where, and how often."""

    enabled: bool = True
    inject_before_body: bool = True
    strip_accept_encoding: bool = True
    only_text_html: bool = True
    chunked_handling: str = "dechunk"  # "dechunk" | "passthrough" | "error"
    domain_whitelist: List[str] = field(default_factory=list)
    path_whitelist: List[str] = field(default_factory=list)
    domain_blacklist: List[str] = field(default_factory=list)
    path_blacklist: List[str] = field(default_factory=list)
    reinjection_delay: int = 5
    throttle_per_target: bool = True


@dataclass
class BeefConfig(_GettableMixin):
    """BeEF REST API connection details for hook monitoring."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 3000
    api_token: Optional[str] = None
    hook_url: Optional[str] = None
    auto_detect_hooks: bool = True
    poll_interval: int = 5


@dataclass
class NetworkConfig(_GettableMixin):
    """Interface and NFQUEUE binding details."""

    interface: str = "eth0"
    queue_num: int = 0
    gateway: Optional[str] = None
    arp_spoof_enabled: bool = False


@dataclass
class LoggingConfig(_GettableMixin):
    """Logging verbosity and destinations."""

    level: str = "INFO"
    verbose: bool = False
    log_file: Optional[str] = None
    log_requests: bool = False
    log_responses: bool = False


@dataclass
class StatsConfig(_GettableMixin):
    """Stats dashboard behavior."""

    enabled: bool = True
    update_interval: int = 1
    dashboard_type: str = "textual"


@dataclass
class Config(_GettableMixin):
    """Top-level configuration bundle."""

    injection: InjectionConfig = field(default_factory=InjectionConfig)
    beef: BeefConfig = field(default_factory=BeefConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    stats: StatsConfig = field(default_factory=StatsConfig)
    targets_file: str = "TARGETS.txt"
    default_payload: str = "eicar"
    custom_payload_file: Optional[str] = None


def _merge_section(instance: Any, overrides: Optional[Dict[str, Any]]) -> None:
    """Apply YAML overrides for keys that exist on the dataclass, in place."""
    if not overrides:
        return
    valid_keys = {f.name for f in fields(instance)}
    for key, value in overrides.items():
        if key in valid_keys:
            setattr(instance, key, value)


def load_config(path: Optional[Path] = None) -> Config:
    """Build a Config from defaults, optionally overridden by a YAML file.

    A missing or unspecified path is not an error -- the tool is expected
    to run with just its defaults for a plain EICAR/BeEF demo.
    """
    config = Config()

    if path is None:
        return config

    if not Path(path).exists():
        return config

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    _merge_section(config.injection, raw.get("injection"))
    _merge_section(config.beef, raw.get("beef"))
    _merge_section(config.network, raw.get("network"))
    _merge_section(config.logging, raw.get("logging"))
    _merge_section(config.stats, raw.get("stats"))

    for key in ("targets_file", "default_payload", "custom_payload_file"):
        if key in raw:
            setattr(config, key, raw[key])

    return config
