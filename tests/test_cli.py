"""Tests for CLI helper methods."""


import pytest

from src.cli import create_injector
from src.config import Config
from src.injectors import (
    AlertTestInjector,
    BeefHookInjector,
    CustomJSInjector,
    EicarTestInjector,
    KeyloggerDemoInjector,
)


class TestCLI:
    def test_create_eicar_injector(self):
        config = Config()
        injector = create_injector("eicar", config)
        assert isinstance(injector, EicarTestInjector)

    def test_create_beef_injector(self):
        config = Config()
        config.beef.host = "10.0.0.1"
        config.beef.port = 8080
        config.beef.hook_url = "http://10.0.0.1:8080/hook.js"

        injector = create_injector("beef", config)
        assert isinstance(injector, BeefHookInjector)
        assert injector.beef_host == "10.0.0.1"
        assert injector.beef_port == 8080
        assert injector.hook_url == "http://10.0.0.1:8080/hook.js"

    def test_create_alert_injector(self):
        config = Config()
        injector = create_injector("alert", config)
        assert isinstance(injector, AlertTestInjector)
        # Verify it has the default message we hardcoded in cli.py
        assert injector.message == "XSS Code Injection Test"

    def test_create_keylogger_injector(self):
        config = Config()
        injector = create_injector("keylogger", config)
        assert isinstance(injector, KeyloggerDemoInjector)

    def test_create_custom_injector_requires_file(self):
        config = Config()
        with pytest.raises(ValueError, match="Custom payload requires --custom-file"):
            create_injector("custom", config)

    def test_create_custom_injector_with_file(self, tmp_path):
        config = Config()
        custom_file = tmp_path / "payload.js"
        custom_file.write_text("console.log('test');")

        injector = create_injector("custom", config, custom_file=str(custom_file))
        assert isinstance(injector, CustomJSInjector)
        assert injector.file_path == str(custom_file)

    def test_create_unknown_injector_raises(self):
        config = Config()
        with pytest.raises(ValueError, match="Unknown payload type: unknown"):
            create_injector("unknown", config)
