"""Pluggable injection strategies module."""

from .base import BaseInjector
from .beef import BeefHookInjector
from .alert import AlertTestInjector
from .keylogger import KeyloggerDemoInjector
from .custom import CustomJSInjector
from .eicar import EicarTestInjector

__all__ = [
    "BaseInjector",
    "BeefHookInjector",
    "AlertTestInjector",
    "KeyloggerDemoInjector",
    "CustomJSInjector",
    "EicarTestInjector",
]
