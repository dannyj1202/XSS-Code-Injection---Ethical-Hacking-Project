"""Tests for PacketHandler core MITM logic (no live network)."""

import re

import pytest
from scapy.all import IP, TCP, Raw

from src.config.settings import InjectionConfig
from src.injectors.eicar import EicarTestInjector
from src.interceptor.packet_handler import PacketHandler


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


def _build_request(src: str, body: bytes) -> bytes:
    pkt = IP(src=src, dst="10.0.0.1") / TCP(sport=44444, dport=80) / Raw(load=body)
    return bytes(pkt)


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


class TestAllowlistGating:
    def test_request_ignored_for_non_target(self, handler: PacketHandler) -> None:
        body = b"GET / HTTP/1.1\r\nHost: lab.local\r\nAccept-Encoding: gzip\r\n\r\n"
        packet = MockNFQPacket(_build_request("192.168.1.200", body))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.accepted
        assert packet.modified is None

    def test_response_ignored_for_non_target(self, handler: PacketHandler) -> None:
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 25\r\n"
            "\r\n"
            "<html><body></body></html>"
        )
        packet = MockNFQPacket(_build_response("192.168.1.200", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.accepted
        assert packet.modified is None


class TestAcceptEncodingStrip:
    def test_strips_accept_encoding_on_target_request(self, handler: PacketHandler) -> None:
        body = b"GET / HTTP/1.1\r\nHost: lab.local\r\nAccept-Encoding: gzip\r\n\r\n"
        packet = MockNFQPacket(_build_request("192.168.1.101", body))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.accepted
        assert packet.modified is not None
        assert b"Accept-Encoding" not in packet.modified
        assert handler.stats.accept_encoding_stripped == 1


class TestHtmlInjection:
    def test_injects_before_body_and_recalculates_content_length(self, handler: PacketHandler) -> None:
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
        assert packet.accepted
        assert packet.modified is not None
        modified = packet.modified.decode("latin-1", errors="ignore")
        assert "</body>" in modified
        assert "EICAR" in modified or "console.log" in modified
        cl_match = re.search(r"Content-Length:\s*(\d+)", modified)
        assert cl_match is not None
        body_start = modified.find("\r\n\r\n") + 4
        actual_body = modified[body_start:]
        assert int(cl_match.group(1)) == len(actual_body.encode("latin-1"))
        assert handler.stats.successful_injections == 1

    def test_skips_non_html_responses(self, handler: PacketHandler) -> None:
        body = '{"ok": true}'
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is None
        assert handler.stats.skipped_responses == 1

    def test_no_modify_when_body_tag_missing(self, handler: PacketHandler) -> None:
        body = "<html><p>no closing body</p></html>"
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is None


class TestChunkedHandling:
    def test_dechunk_inject_and_set_content_length(self, handler: PacketHandler) -> None:
        # len("HelloWorld</body>") == 17 == 0x11
        chunked = "11\r\nHelloWorld</body>\r\n0\r\n\r\n"
        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            f"{chunked}"
        )
        packet = MockNFQPacket(_build_response("192.168.1.101", http))
        handler.handle_packet(packet)  # type: ignore[arg-type]
        assert packet.modified is not None
        modified = packet.modified.decode("latin-1", errors="ignore")
        assert "Transfer-Encoding" not in modified
        assert "Content-Length:" in modified
        assert handler.stats.chunked_responses == 1


class TestDechunkUnit:
    def test_dechunk_body_matches_demo_logic(self, handler: PacketHandler) -> None:
        chunked = "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"
        assert handler._dechunk_body(chunked) == "HelloWorld"
