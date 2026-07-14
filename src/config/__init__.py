"""Configuration and safety-control module.

Exposes the safety gate (``SafetyConfig``) and the YAML-backed settings
loader (``load_config``) used throughout the CLI and interceptor.
"""

from .safety import EICAR_TEST_STRING, SafetyConfig, SafetyValidationError
from .settings import (
    BeefConfig,
    Config,
    InjectionConfig,
    LoggingConfig,
    NetworkConfig,
    StatsConfig,
    load_config,
)

__all__ = [
    "EICAR_TEST_STRING",
    "SafetyConfig",
    "SafetyValidationError",
    "Config",
    "InjectionConfig",
    "NetworkConfig",
    "BeefConfig",
    "LoggingConfig",
    "StatsConfig",
    "load_config",
]
