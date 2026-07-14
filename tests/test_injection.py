"""Unit tests for injection logic.

Tests Content-Length math, chunked handling, allowlist gating, and
injection strategies using actual class instances — not inline
reimplementations — so regressions in the real code are caught.
"""

import re

import pytest
from scapy.all import IP, TCP, Raw

from src.config.safety import SafetyConfig, SafetyValidationError, _is_private
from src.config.settings import InjectionConfig
from src.injectors.alert import AlertTestInjector
from src.injectors.beef import BeefHookInjector
from src.injectors.eicar import EicarTestInjector
from src.interceptor.packet_handler import PacketHandler

# ---------------------------------------------------------------------------
# Helpers (shared with test_packet_handler.py but kept local to avoid deps)
# ---------------------------------------------------------------------------

class MockNFQPacket:
    def __init__(self, scapy_bytes: bytes):
        self._payload = scapy_bytes
        self.accepted = False
        self.modified: bytes | None = None

    def get_payload(self) -> bytes:
        return self._payload

    def set_payload(self, payload: bytes) -> None:
        self.modified = payload

    def accept(self) -> None:
        self.accepted = True


def _build_response(dst: str, http: str) -> bytes:
    pkt = IP(src="10.0.0.1", dst=dst) / TCP(sport=80, dport=44444) / Raw(load=http.encode("latin-1"))
    return bytes(pkt)


@pytest.fixture
def handler() -> PacketHandler:
    return PacketHandler(
        injector=EicarTestInjector(),
        config=InjectionConfig(),
        targets={"192.168.1.101"},
        verbose=False,
    )


# ---------------------------------------------------------------------------
# Safety validation — exercises real SafetyConfig / _is_private
# ---------------------------------------------------------------------------

class TestSafetyValidation:
    """Test safety validation logic using real classes."""

    def test_validate_rfc1918_valid_private_ips(self):
        valid_ips = [
            "10.0.0.1", "10.255.255.254",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
        ]
        for ip_str in valid_ips:
            assert _is_private(ip_str) is True, f"{ip_str} should be private"

    def test_validate_rfc1918_invalid_public_ips(self):
        public_ips = ["8.8.8.8", "1.1.1.1", "172.15.255.255", "192.169.0.1"]
        for ip_str in public_ips:
            assert _is_private(ip_str) is False, f"{ip_str} should not be private"

    def test_invalid_ip_raises(self):
        with pytest.raises(SafetyValidationError, match="not a valid IP"):
            _is_private("not-an-ip")

    def test_safety_config_rejects_empty_file(self, tmp_path):
        targets = tmp_path / "TARGETS.txt"
        targets.write_text("# only comments\n")
        sc = SafetyConfig(targets)
        with pytest.raises(SafetyValidationError, match="no IP"):
            sc.validate(i_have_authorization=True)


# ---------------------------------------------------------------------------
# Content-Length recalculation — through real PacketHandler
# ---------------------------------------------------------------------------

class TestContentLengthMath:
    """Test Content-Length calculation via real PacketHandler flow."""

    def test_content_length_updated_after_injection(self, handler: PacketHandler):
        body = "<html><body>Hello</body></html>"
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is not None
        modified = packet.modified.decode("latin-1", errors="ignore")
        body_start = modified.find("\r\n\r\n") + 4
        actual_body = modified[body_start:]
        cl_match = re.search(r"Content-Length:\s*(\d+)", modified)
        assert cl_match is not None
        assert int(cl_match.group(1)) == len(actual_body.encode("latin-1"))

    def test_content_length_no_body_tag_no_change(self, handler: PacketHandler):
        body = "<html><p>No body tag</p></html>"
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is None  # no injection point → no modification

    def test_content_length_with_latin1_body(self, handler: PacketHandler):
        """Latin-1 chars (e.g. accented) must not desync Content-Length."""
        body = "<html><body>Héllo café</body></html>"
        raw_bytes = body.encode("latin-1")
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(raw_bytes)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is not None
        modified = packet.modified.decode("latin-1", errors="ignore")
        body_start = modified.find("\r\n\r\n") + 4
        actual_body = modified[body_start:]
        cl_match = re.search(r"Content-Length:\s*(\d+)", modified)
        assert cl_match is not None
        assert int(cl_match.group(1)) == len(actual_body.encode("latin-1"))


# ---------------------------------------------------------------------------
# Chunked handling — via real PacketHandler._dechunk_body
# ---------------------------------------------------------------------------

class TestChunkedHandling:
    """Test chunked transfer encoding handling via real method."""

    def test_dechunk_simple(self, handler: PacketHandler):
        chunked = "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"
        assert handler._dechunk_body(chunked) == "HelloWorld"

    def test_dechunk_empty(self, handler: PacketHandler):
        assert handler._dechunk_body("0\r\n\r\n") == ""

    def test_dechunk_single_chunk(self, handler: PacketHandler):
        # 0xa == 10
        assert handler._dechunk_body("a\r\n0123456789\r\n0\r\n\r\n") == "0123456789"

    def test_dechunk_html_with_crlf(self, handler: PacketHandler):
        """Chunk data containing \\r\\n must be reassembled correctly."""
        html = "<html>\r\n<body>Hi</body>\r\n</html>"
        size = len(html)
        chunked = f"{size:x}\r\n{html}\r\n0\r\n\r\n"
        assert handler._dechunk_body(chunked) == html


# ---------------------------------------------------------------------------
# Injector classes — exercise real instances
# ---------------------------------------------------------------------------

class TestInjectors:
    """Test injection strategy classes produce valid payloads."""

    def test_eicar_payload_structure(self):
        injector = EicarTestInjector()
        payload = injector.get_payload()
        assert "<script>" in payload
        assert "</script>" in payload
        assert "EICAR" in payload
        assert injector.should_inject("<html><body></body></html>")
        assert not injector.should_inject("<html><p>no body tag</p></html>")

    def test_beef_payload_structure(self):
        injector = BeefHookInjector({"host": "172.16.0.1", "port": 3000})
        payload = injector.get_payload()
        assert "<script src=" in payload
        assert "</script>" in payload
        assert "172.16.0.1" in payload
        assert "3000" in payload
        assert injector.validate_payload(payload)

    def test_beef_custom_hook_url(self):
        injector = BeefHookInjector({"hook_url": "http://10.0.0.5:4000/hook.js"})
        assert "10.0.0.5:4000" in injector.get_payload()

    def test_alert_payload_structure(self):
        injector = AlertTestInjector({"message": "Test Alert"})
        payload = injector.get_payload()
        assert "<script>" in payload
        assert "alert(" in payload
        assert "Test Alert" in payload

    def test_alert_escapes_quotes(self):
        injector = AlertTestInjector({"message": 'He said "hi"'})
        payload = injector.get_payload()
        assert '\\"' in payload  # quotes must be escaped


# ---------------------------------------------------------------------------
# Targeting rules — via real PacketHandler
# ---------------------------------------------------------------------------

class TestTargetingRules:
    """Test injection targeting rules via real PacketHandler."""

    def test_domain_whitelist_allows(self):
        config = InjectionConfig(domain_whitelist=["example.com"])
        handler = PacketHandler(
            injector=EicarTestInjector(), config=config,
            targets={"192.168.1.101"}, verbose=False,
        )
        headers = {"Host": "example.com", "Content-Type": "text/html"}
        assert handler._check_targeting_rules(headers, "") is True

    def test_domain_whitelist_blocks(self):
        config = InjectionConfig(domain_whitelist=["example.com"])
        handler = PacketHandler(
            injector=EicarTestInjector(), config=config,
            targets={"192.168.1.101"}, verbose=False,
        )
        headers = {"Host": "other.com", "Content-Type": "text/html"}
        assert handler._check_targeting_rules(headers, "") is False

    def test_domain_blacklist_blocks(self):
        config = InjectionConfig(domain_blacklist=["evil.com"])
        handler = PacketHandler(
            injector=EicarTestInjector(), config=config,
            targets={"192.168.1.101"}, verbose=False,
        )
        headers = {"Host": "evil.com", "Content-Type": "text/html"}
        assert handler._check_targeting_rules(headers, "") is False


# ---------------------------------------------------------------------------
# Throttling — via real PacketHandler
# ---------------------------------------------------------------------------

class TestThrottling:
    """Test injection throttling via real PacketHandler."""

    def test_first_injection_not_throttled(self, handler: PacketHandler):
        assert handler._is_throttled("new_session") is False

    def test_immediate_reinjection_throttled(self, handler: PacketHandler):
        from datetime import datetime
        handler.session_injection_times["sess1"] = datetime.now()
        assert handler._is_throttled("sess1") is True

    def test_throttling_expires(self, handler: PacketHandler):
        from datetime import datetime, timedelta
        handler.session_injection_times["sess2"] = datetime.now() - timedelta(seconds=999)
        assert handler._is_throttled("sess2") is False


# ---------------------------------------------------------------------------
# Config — via real dataclass
# ---------------------------------------------------------------------------

class TestConfig:
    """Test configuration defaults using real InjectionConfig."""

    def test_default_config_values(self):
        config = InjectionConfig()
        assert config.enabled is True
        assert config.only_text_html is True
        assert config.strip_accept_encoding is True
        assert config.chunked_handling == "dechunk"
        assert config.reinjection_delay == 5


# ---------------------------------------------------------------------------
# Stats — via real InjectionStats
# ---------------------------------------------------------------------------

class TestInjectionStats:
    """Test injection statistics tracking via real PacketHandler."""

    def test_stats_initialization(self, handler: PacketHandler):
        stats = handler.get_stats()
        assert stats.packets_processed == 0
        assert stats.successful_injections == 0

    def test_stats_increment_on_injection(self, handler: PacketHandler):
        body = "<html><body>test</body></html>"
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        stats = handler.get_stats()
        assert stats.packets_processed == 1
        assert stats.successful_injections == 1

    def test_reset_stats(self, handler: PacketHandler):
        handler.stats.packets_processed = 42
        handler.reset_stats()
        assert handler.get_stats().packets_processed == 0
