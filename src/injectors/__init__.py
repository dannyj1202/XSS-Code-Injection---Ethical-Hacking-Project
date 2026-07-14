"""Pluggable injection strategies module."""

from .alert import AlertTestInjector
from .base import BaseInjector
from .beef import BeefHookInjector
from .custom import CustomJSInjector
from .eicar import EicarTestInjector
from .keylogger import KeyloggerDemoInjector

__all__ = [
    "BaseInjector",
    "BeefHookInjector",
    "AlertTestInjector",
    "KeyloggerDemoInjector",
    "CustomJSInjector",
    "EicarTestInjector",
]
