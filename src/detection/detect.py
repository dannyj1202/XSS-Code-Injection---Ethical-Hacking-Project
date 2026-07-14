#!/usr/bin/env python3
"""
Defensive companion for detecting XSS Code Injection attacks.

This module demonstrates how a blue team can detect MITM JavaScript injection
attacks by monitoring for:
- Unexpected ARP changes
- Injected <script> tags in known-clean pages
- Content-Length anomalies
- Accept-Encoding header stripping

This is for educational purposes to understand both offense and defense.
"""

import argparse
import re
import time
from dataclasses import dataclass
from datetime import datetime

import requests


@dataclass
class ARPEntry:
    """ARP table entry."""

    ip: str
    mac: str
    interface: str
    last_seen: datetime


@dataclass
class DetectionAlert:
    """Security detection alert."""

    alert_type: str
    severity: str
    message: str
    timestamp: datetime
    details: dict


class ARPMonitor:
    """
    Monitor ARP table for suspicious changes.

    MITM attacks often involve ARP spoofing, which changes MAC-IP mappings.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize ARP monitor.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.arp_cache: dict[str, ARPEntry] = {}
        self.gateway_mac: str | None = None
        self.alerts: list[DetectionAlert] = []

    def get_arp_table(self) -> list[ARPEntry]:
        """
        Get current ARP table.

        Returns:
            List of ARPEntry objects
        """
        try:
            # Linux: read /proc/net/arp
            with open("/proc/net/arp") as f:
                lines = f.readlines()[1:]  # Skip header

            entries = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3]
                    interface = parts[5]

                    if mac != "00:00:00:00:00:00":  # Skip incomplete entries
                        entry = ARPEntry(
                            ip=ip, mac=mac, interface=interface, last_seen=datetime.now()
                        )
                        entries.append(entry)

            return entries

        except Exception as e:
            print(f"Error reading ARP table: {e}")
            return []

    def detect_arp_changes(self) -> list[DetectionAlert]:
        """
        Detect suspicious ARP changes.

        Returns:
            List of detection alerts
        """
        current_entries = self.get_arp_table()
        new_alerts = []

        for entry in current_entries:
            ip = entry.ip

            # Check if this is a new entry
            if ip not in self.arp_cache:
                self.arp_cache[ip] = entry
                continue

            # Check if MAC has changed
            cached_entry = self.arp_cache[ip]
            if cached_entry.mac != entry.mac:
                alert = DetectionAlert(
                    alert_type="ARP_SPOOF_DETECTED",
                    severity="HIGH",
                    message=f"MAC address changed for {ip}: {cached_entry.mac} -> {entry.mac}",
                    timestamp=datetime.now(),
                    details={
                        "ip": ip,
                        "old_mac": cached_entry.mac,
                        "new_mac": entry.mac,
                        "interface": entry.interface,
                    },
                )
                new_alerts.append(alert)
                self.alerts.append(alert)

                # Update cache
                self.arp_cache[ip] = entry

        return new_alerts

    def monitor(self, interval: int = 5) -> None:
        """
        Continuously monitor ARP table for changes.

        Args:
            interval: Seconds between checks
        """
        print(f"Starting ARP monitoring (checking every {interval}s)...")
        print("Press Ctrl+C to stop\n")

        try:
            while True:
                alerts = self.detect_arp_changes()

                for alert in alerts:
                    self._print_alert(alert)

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\nARP monitoring stopped")

    def _print_alert(self, alert: DetectionAlert) -> None:
        """Print a detection alert."""
        print(f"\n{'!'*60}")
        print(f"⚠️  {alert.alert_type}")
        print(f"Severity: {alert.severity}")
        print(f"Time: {alert.timestamp}")
        print(f"Message: {alert.message}")
        print(f"Details: {alert.details}")
        print(f"{'!'*60}\n")


class ContentLengthMonitor:
    """
    Monitor for Content-Length anomalies.

    MITM injection attacks often modify Content-Length after injection.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize Content-Length monitor.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.alerts: list[DetectionAlert] = []

    def check_response(self, response: requests.Response) -> DetectionAlert | None:
        """
        Check HTTP response for Content-Length anomalies.

        Args:
            response: HTTP response object

        Returns:
            DetectionAlert if anomaly found, None otherwise
        """
        content_length_header = response.headers.get("Content-Length")
        actual_length = len(response.content)

        if content_length_header:
            try:
                reported_length = int(content_length_header)

                # Allow small tolerance for encoding differences
                if abs(reported_length - actual_length) > 100:
                    alert = DetectionAlert(
                        alert_type="CONTENT_LENGTH_MISMATCH",
                        severity="MEDIUM",
                        message=f"Content-Length mismatch: reported={reported_length}, actual={actual_length}",
                        timestamp=datetime.now(),
                        details={
                            "url": response.url,
                            "reported_length": reported_length,
                            "actual_length": actual_length,
                            "difference": abs(reported_length - actual_length),
                        },
                    )
                    self.alerts.append(alert)
                    return alert

            except ValueError:
                pass

        return None


class ScriptInjectionDetector:
    """
    Detect injected JavaScript in HTTP responses.

    This checks for unexpected <script> tags in responses.
    """

    def __init__(self, known_clean_urls: set[str], verbose: bool = False):
        """
        Initialize script injection detector.

        Args:
            known_clean_urls: Set of URLs that should not have scripts
            verbose: Enable verbose output
        """
        self.known_clean_urls = known_clean_urls
        self.verbose = verbose
        self.alerts: list[DetectionAlert] = []

    def check_for_injection(self, response: requests.Response) -> DetectionAlert | None:
        """
        Check response for injected scripts.

        Args:
            response: HTTP response object

        Returns:
            DetectionAlert if injection found, None otherwise
        """
        # Only check known-clean URLs
        if response.url not in self.known_clean_urls:
            return None

        content = response.text

        # Check for script tags
        script_pattern = r"<script[^>]*>.*?</script>"
        scripts = re.findall(script_pattern, content, re.IGNORECASE | re.DOTALL)

        if scripts:
            alert = DetectionAlert(
                alert_type="SCRIPT_INJECTION_DETECTED",
                severity="HIGH",
                message=f"Unexpected script tags found in known-clean URL: {response.url}",
                timestamp=datetime.now(),
                details={
                    "url": response.url,
                    "script_count": len(scripts),
                    "scripts": scripts[:3],  # First 3 scripts
                },
            )
            self.alerts.append(alert)
            return alert

        return None


class AcceptEncodingMonitor:
    """
    Monitor for Accept-Encoding header stripping.

    MITM attacks often strip Accept-Encoding to defeat compression.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize Accept-Encoding monitor.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.alerts: list[DetectionAlert] = []

    def check_request(self, request_headers: dict) -> DetectionAlert | None:
        """
        Check if Accept-Encoding was stripped from request.

        Args:
            request_headers: HTTP request headers

        Returns:
            DetectionAlert if stripping detected, None otherwise
        """
        accept_encoding = request_headers.get("Accept-Encoding", "")

        # If Accept-Encoding is missing or empty, it might have been stripped
        if not accept_encoding or accept_encoding == "identity":
            alert = DetectionAlert(
                alert_type="ACCEPT_ENCODING_STRIPPED",
                severity="MEDIUM",
                message="Accept-Encoding header missing or set to identity (possible MITM)",
                timestamp=datetime.now(),
                details={"accept_encoding": accept_encoding},
            )
            self.alerts.append(alert)
            return alert

        return None


class BlueTeamDetector:
    """
    Comprehensive blue team detection suite.

    This combines multiple detection methods to identify MITM injection attacks.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize blue team detector.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.arp_monitor = ARPMonitor(verbose)
        self.content_length_monitor = ContentLengthMonitor(verbose)
        self.script_detector = ScriptInjectionDetector(set(), verbose)
        self.encoding_monitor = AcceptEncodingMonitor(verbose)

        self.all_alerts: list[DetectionAlert] = []

    def run_comprehensive_scan(self) -> None:
        """Run a comprehensive security scan."""
        print("=" * 60)
        print("Blue Team Detection Suite")
        print("=" * 60)
        print()

        # ARP monitoring
        print("1. Checking for ARP spoofing...")
        arp_alerts = self.arp_monitor.detect_arp_changes()
        if arp_alerts:
            print(f"   ⚠️  Found {len(arp_alerts)} ARP anomalies")
            for alert in arp_alerts:
                self._print_alert(alert)
        else:
            print("   ✓ No ARP anomalies detected")
        print()

        # Summary
        print("=" * 60)
        print("Scan Complete")
        print(f"Total alerts: {len(self.all_alerts)}")
        print("=" * 60)

    def start_arp_monitoring(self, interval: int = 5) -> None:
        """
        Start continuous ARP monitoring.

        Args:
            interval: Seconds between checks
        """
        self.arp_monitor.monitor(interval)

    def _print_alert(self, alert: DetectionAlert) -> None:
        """Print a detection alert."""
        print(f"\n{'!'*60}")
        print(f"⚠️  {alert.alert_type}")
        print(f"Severity: {alert.severity}")
        print(f"Time: {alert.timestamp}")
        print(f"Message: {alert.message}")
        print(f"{'!'*60}\n")
        self.all_alerts.append(alert)


def main():
    """Main entry point for defensive detection."""
    parser = argparse.ArgumentParser(
        description="Blue Team Detection Suite for XSS Code Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run comprehensive scan
  python detect.py --scan

  # Monitor ARP table continuously
  python detect.py --monitor-arp

  # Monitor ARP with custom interval
  python detect.py --monitor-arp --interval 10
        """,
    )

    parser.add_argument("--scan", action="store_true", help="Run comprehensive security scan")

    parser.add_argument("--monitor-arp", action="store_true", help="Monitor ARP table for changes")

    parser.add_argument(
        "--interval", type=int, default=5, help="Monitoring interval in seconds (default: 5)"
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    detector = BlueTeamDetector(verbose=args.verbose)

    if args.scan:
        detector.run_comprehensive_scan()
    elif args.monitor_arp:
        detector.start_arp_monitoring(interval=args.interval)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
