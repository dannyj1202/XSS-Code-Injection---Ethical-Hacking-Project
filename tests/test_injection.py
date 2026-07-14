"""
Unit tests for injection logic.

Tests Content-Length math, chunked handling, allowlist gating, and
injection strategies without requiring a live network.
"""

import pytest
from pathlib import Path
from src.config.safety import SafetyConfig, validate_rfc1918, SafetyError
from src.config.settings import Config, load_config
from src.injectors.eicar import EicarTestInjector
from src.injectors.beef import BeefHookInjector
from src.injectors.alert import AlertTestInjector
from src.injectors.custom import CustomJSInjector
from src.interceptor.packet_handler import PacketHandler, InjectionStats


class TestSafetyValidation:
    """Test safety validation logic."""
    
    def test_validate_rfc1918_valid_private_ips(self):
        """Test that valid RFC1918 private IPs pass validation."""
        assert validate_rfc1918("10.0.0.1") is True
        assert validate_rfc1918("10.255.255.254") is True
        assert validate_rfc1918("172.16.0.1") is True
        assert validate_rfc1918("172.31.255.254") is True
        assert validate_rfc1918("192.168.0.1") is True
        assert validate_rfc1918("192.168.255.254") is True
    
    def test_validate_rfc1918_invalid_public_ips(self):
        """Test that public IPs fail validation."""
        with pytest.raises(SafetyError):
            validate_rfc1918("8.8.8.8")
        
        with pytest.raises(SafetyError):
            validate_rfc1918("1.1.1.1")
        
        with pytest.raises(SafetyError):
            validate_rfc1918("172.15.255.255")  # Just outside 172.16/12
        
        with pytest.raises(SafetyError):
            validate_rfc1918("192.169.0.1")  # Just outside 192.168/16
    
    def test_validate_rfc1918_invalid_format(self):
        """Test that invalid IP formats fail validation."""
        with pytest.raises(SafetyError):
            validate_rfc1918("not-an-ip")
        
        with pytest.raises(SafetyError):
            validate_rfc1918("256.0.0.1")
    
    def test_safety_config_authorization_required(self):
        """Test that authorization flag is required."""
        safety_config = SafetyConfig()
        
        with pytest.raises(SafetyError):
            safety_config.check_authorization(False)
        
        # Should not raise when True
        safety_config.check_authorization(True)
        assert safety_config.authorized is True


class TestContentLengthMath:
    """Test Content-Length calculation after injection."""
    
    def test_content_length_calculation_basic(self):
        """Test basic Content-Length calculation."""
        original_html = "<html><body>Hello</body></html>"
        payload = "<script>console.log('test');</script>"
        
        original_length = len(original_html.encode('utf-8'))
        injected_html = original_html.replace("</body>", payload + "</body>")
        new_length = len(injected_html.encode('utf-8'))
        
        expected_increase = len(payload.encode('utf-8'))
        assert new_length == original_length + expected_increase
    
    def test_content_length_with_multibyte_chars(self):
        """Test Content-Length with multibyte UTF-8 characters."""
        original_html = "<html><body>Héllo 世界</body></html>"
        payload = "<script>console.log('test');</script>"
        
        original_length = len(original_html.encode('utf-8'))
        injected_html = original_html.replace("</body>", payload + "</body>")
        new_length = len(injected_html.encode('utf-8'))
        
        payload_length = len(payload.encode('utf-8'))
        assert new_length == original_length + payload_length
    
    def test_content_length_no_body_tag(self):
        """Test that Content-Length doesn't change when no body tag exists."""
        original_html = "<html><p>No body tag</p></html>"
        payload = "<script>console.log('test');</script>"
        
        original_length = len(original_html.encode('utf-8'))
        
        # No injection should occur
        injected_html = original_html.replace("</body>", payload + "</body>")
        new_length = len(injected_html.encode('utf-8'))
        
        # Should be the same since no replacement occurred
        assert new_length == original_length


class TestChunkedHandling:
    """Test chunked transfer encoding handling."""
    
    def test_dechunk_simple(self):
        """Test de-chunking a simple chunked response."""
        chunked_body = "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"
        
        # Create a mock packet handler
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        
        # Test dechunking logic
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        dechunked = handler._dechunk_body(chunked_body)
        assert dechunked == "HelloWorld"
    
    def test_dechunk_empty(self):
        """Test de-chunking an empty response."""
        chunked_body = "0\r\n\r\n"
        
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        dechunked = handler._dechunk_body(chunked_body)
        assert dechunked == ""
    
    def test_dechunk_single_chunk(self):
        """Test de-chunking a single chunk."""
        chunked_body = "a\r\n0123456789\r\n0\r\n\r\n"
        
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        dechunked = handler._dechunk_body(chunked_body)
        assert dechunked == "0123456789"


class TestInjectors:
    """Test injection strategies."""
    
    def test_eicar_injector(self):
        """Test EICAR injector generates valid payload."""
        injector = EicarTestInjector()
        payload = injector.get_payload()
        
        assert "<script>" in payload
        assert "</script>" in payload
        assert "EICAR" in payload
        assert injector.should_inject("<html><body></body></html>") is True
    
    def test_beef_injector(self):
        """Test BeEF injector generates valid payload."""
        config = {'host': '127.0.0.1', 'port': 3000}
        injector = BeefHookInjector(config)
        payload = injector.get_payload()
        
        assert "<script src=" in payload
        assert "</script>" in payload
        assert "127.0.0.1" in payload
        assert "3000" in payload
    
    def test_alert_injector(self):
        """Test alert injector generates valid payload."""
        config = {'message': 'Test Alert'}
        injector = AlertTestInjector(config)
        payload = injector.get_payload()
        
        assert "<script>" in payload
        assert "alert(" in payload
        assert "Test Alert" in payload
        assert "</script>" in payload
    
    def test_custom_injector(self):
        """Test custom JS injector loads from file."""
        # Create a temporary JS file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("console.log('custom payload');")
            temp_file = f.name
        
        try:
            config = {'file_path': temp_file}
            injector = CustomJSInjector(config)
            payload = injector.get_payload()
            
            assert "<script>" in payload
            assert "console.log('custom payload');" in payload
            assert "</script>" in payload
        finally:
            Path(temp_file).unlink()
    
    def test_custom_injector_file_not_found(self):
        """Test custom injector raises error for missing file."""
        config = {'file_path': '/nonexistent/file.js'}
        injector = CustomJSInjector(config)
        
        with pytest.raises(FileNotFoundError):
            injector._load_payload()


class TestTargetingRules:
    """Test injection targeting rules."""
    
    def test_domain_whitelist(self):
        """Test domain whitelist filtering."""
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        config.domain_whitelist = ['example.com']
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        # Should allow whitelisted domain
        headers = {'Host': 'example.com'}
        assert handler._check_targeting_rules(headers, "<body></body>") is True
        
        # Should block non-whitelisted domain
        headers = {'Host': 'other.com'}
        assert handler._check_targeting_rules(headers, "<body></body>") is False
    
    def test_domain_blacklist(self):
        """Test domain blacklist filtering."""
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        config.domain_blacklist = ['evil.com']
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        # Should block blacklisted domain
        headers = {'Host': 'evil.com'}
        assert handler._check_targeting_rules(headers, "<body></body>") is False
        
        # Should allow non-blacklisted domain
        headers = {'Host': 'good.com'}
        assert handler._check_targeting_rules(headers, "<body></body>") is True
    
    def test_no_restrictions(self):
        """Test that no restrictions allow all domains."""
        from src.config.settings import InjectionConfig
        config = InjectionConfig()
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        headers = {'Host': 'any-domain.com'}
        assert handler._check_targeting_rules(headers, "<body></body>") is True


class TestThrottling:
    """Test injection throttling logic."""
    
    def test_throttling_enabled(self):
        """Test that throttling prevents rapid re-injection."""
        from src.config.settings import InjectionConfig
        from datetime import datetime, timedelta
        
        config = InjectionConfig()
        config.throttle_per_target = True
        config.reinjection_delay = 5
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        headers = {'User-Agent': 'TestAgent'}
        session_id = handler._get_session_id(headers, "192.168.1.1")
        
        # First injection should not be throttled
        assert handler._is_throttled(session_id) is False
        
        # Record injection
        handler.session_injection_times[session_id] = datetime.now()
        
        # Immediate re-injection should be throttled
        assert handler._is_throttled(session_id) is True
    
    def test_throttling_disabled(self):
        """Test that disabled throttling allows rapid re-injection."""
        from src.config.settings import InjectionConfig
        from datetime import datetime
        
        config = InjectionConfig()
        config.throttle_per_target = False
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        headers = {'User-Agent': 'TestAgent'}
        session_id = handler._get_session_id(headers, "192.168.1.1")
        
        # Record injection
        handler.session_injection_times[session_id] = datetime.now()
        
        # Should not be throttled when disabled
        assert handler._is_throttled(session_id) is False
    
    def test_throttling_expires(self):
        """Test that throttling expires after delay."""
        from src.config.settings import InjectionConfig
        from datetime import datetime, timedelta
        
        config = InjectionConfig()
        config.throttle_per_target = True
        config.reinjection_delay = 1
        
        handler = PacketHandler(
            injector=EicarTestInjector(),
            config=config,
            targets={"192.168.1.1"},
            verbose=False
        )
        
        headers = {'User-Agent': 'TestAgent'}
        session_id = handler._get_session_id(headers, "192.168.1.1")
        
        # Record injection in the past
        handler.session_injection_times[session_id] = datetime.now() - timedelta(seconds=2)
        
        # Should not be throttled after delay expires
        assert handler._is_throttled(session_id) is False


class TestConfig:
    """Test configuration management."""
    
    def test_default_config(self):
        """Test that default config is valid."""
        config = Config()
        
        assert config.injection.enabled is True
        assert config.injection.only_text_html is True
        assert config.network.queue_num == 0
        assert config.logging.level == "INFO"
    
    def test_load_config_missing_file(self):
        """Test loading config when file doesn't exist."""
        config = load_config(Path("nonexistent.yaml"))
        
        # Should return default config
        assert config.injection.enabled is True
        assert config.network.queue_num == 0


class TestInjectionStats:
    """Test injection statistics tracking."""
    
    def test_stats_initialization(self):
        """Test that stats initialize correctly."""
        stats = InjectionStats()
        
        assert stats.packets_processed == 0
        assert stats.http_responses_seen == 0
        assert stats.injection_attempts == 0
        assert stats.successful_injections == 0
    
    def test_stats_increment(self):
        """Test that stats increment correctly."""
        stats = InjectionStats()
        
        stats.packets_processed += 100
        stats.http_responses_seen += 50
        stats.injection_attempts += 10
        stats.successful_injections += 5
        
        assert stats.packets_processed == 100
        assert stats.http_responses_seen == 50
        assert stats.injection_attempts == 10
        assert stats.successful_injections == 5
