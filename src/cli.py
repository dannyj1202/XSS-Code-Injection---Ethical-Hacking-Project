"""
Command-line interface for XSS Code Injection tool.

This module provides the CLI using argparse for user interaction.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .auto_hook import AutoHookAgent
from .beef_integration import BeEFIntegration
from .config import SafetyConfig, load_config
from .injectors import (
    AlertTestInjector,
    BaseInjector,
    BeefHookInjector,
    CustomJSInjector,
    EicarTestInjector,
    KeyloggerDemoInjector,
)
from .interceptor import NFQueueLoop
from .logging_config import setup_logging
from .mitm import ARPSpoofer, IptablesManager, ShutdownCoordinator


def create_injector(
    payload_type: str, config: dict, custom_file: Optional[str] = None
) -> BaseInjector:
    """
    Create an injector instance based on payload type.

    Args:
        payload_type: Type of payload (eicar, beef, alert, keylogger, custom)
        config: Configuration dictionary
        custom_file: Path to custom JS file (for custom payload)

    Returns:
        BaseInjector instance
    """
    injector_config = {}

    if payload_type == "eicar":
        return EicarTestInjector(injector_config)

    elif payload_type == "beef":
        injector_config = {
            "host": config.get("beef", {}).get("host", "127.0.0.1"),
            "port": config.get("beef", {}).get("port", 3000),
            "hook_url": config.get("beef", {}).get("hook_url"),
        }
        return BeefHookInjector(injector_config)

    elif payload_type == "alert":
        injector_config = {"message": config.get("alert_message", "XSS Code Injection Test")}
        return AlertTestInjector(injector_config)

    elif payload_type == "keylogger":
        injector_config = {"max_log_entries": config.get("keylogger_max_entries", 50)}
        return KeyloggerDemoInjector(injector_config)

    elif payload_type == "custom":
        if not custom_file:
            raise ValueError("Custom payload requires --custom-file argument")
        injector_config = {"file_path": custom_file}
        return CustomJSInjector(injector_config)

    else:
        raise ValueError(f"Unknown payload type: {payload_type}")


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="XSS Code Injection - Ethical Hacking Project\n"
        "A security research tool for demonstrating MITM JavaScript injection "
        "in controlled lab environments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic interception with EICAR test payload
  python -m src.cli --i-have-authorization

  # Use BeEF hook payload
  python -m src.cli --i-have-authorization --payload beef --beef-host 127.0.0.1 --beef-port 3000

  # Auto-hook mode with network discovery
  python -m src.cli --i-have-authorization --auto-hook --subnet 192.168.1.0/24

  # Custom JavaScript payload
  python -m src.cli --i-have-authorization --payload custom --custom-file payload.js

  # Enable ARP spoofing
  python -m src.cli --i-have-authorization --arp-spoof --gateway 192.168.1.1
        """,
    )

    # Mandatory safety arguments
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Required: Confirm you have written authorization for all targets",
    )

    parser.add_argument(
        "--targets-file",
        default="TARGETS.txt",
        help="Path to TARGETS.txt allowlist file (default: TARGETS.txt)",
    )

    # Payload selection
    parser.add_argument(
        "--payload",
        choices=["eicar", "beef", "alert", "keylogger", "custom"],
        default="eicar",
        help="Payload type to inject (default: eicar)",
    )

    parser.add_argument(
        "--custom-file", help="Path to custom JavaScript file (required for --payload custom)"
    )

    # Network configuration
    parser.add_argument("--interface", default="eth0", help="Network interface (default: eth0)")

    parser.add_argument("--queue-num", type=int, default=0, help="NFQUEUE number (default: 0)")

    parser.add_argument(
        "--setup-iptables",
        action="store_true",
        help="Install NFQUEUE/MASQUERADE iptables rules on start (always flushed on exit)",
    )

    parser.add_argument("--gateway", help="Gateway IP address (required for ARP spoofing)")

    # ARP spoofing
    parser.add_argument(
        "--arp-spoof", action="store_true", help="Enable ARP spoofing for MITM positioning"
    )

    # Auto-hook mode
    parser.add_argument(
        "--auto-hook",
        action="store_true",
        help="Enable auto-hook agent mode (discover, spoof, inject, monitor)",
    )

    parser.add_argument("--subnet", help="Subnet to scan in auto-hook mode (e.g., 192.168.1.0/24)")

    # BeEF integration
    parser.add_argument(
        "--beef-host", default="127.0.0.1", help="BeEF server host (default: 127.0.0.1)"
    )

    parser.add_argument(
        "--beef-port", type=int, default=3000, help="BeEF server port (default: 3000)"
    )

    parser.add_argument("--beef-api-token", help="BeEF REST API token for hook monitoring")

    parser.add_argument("--monitor-beef", action="store_true", help="Enable BeEF hook monitoring")

    # Logging
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument("--log-file", help="Path to log file")

    parser.add_argument("--log-requests", action="store_true", help="Log HTTP requests")

    parser.add_argument("--log-responses", action="store_true", help="Log HTTP responses")

    # Configuration
    parser.add_argument("--config", help="Path to config.yaml file")

    args = parser.parse_args()

    # Load configuration
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    # Override config with CLI arguments
    config.network.interface = args.interface
    config.network.queue_num = args.queue_num
    if args.gateway:
        config.network.gateway = args.gateway
    config.network.arp_spoof_enabled = args.arp_spoof

    config.beef.host = args.beef_host
    config.beef.port = args.beef_port
    if args.beef_api_token:
        config.beef.api_token = args.beef_api_token
    config.beef.enabled = args.monitor_beef

    config.logging.verbose = args.verbose
    if args.log_file:
        config.logging.log_file = args.log_file
    config.logging.log_requests = args.log_requests
    config.logging.log_responses = args.log_responses

    # Setup logging
    setup_logging(config.logging)

    # Safety validation
    try:
        safety_config = SafetyConfig(targets_file=Path(args.targets_file))
        safety_config.validate(args.i_have_authorization)
    except Exception as e:
        print(f"Safety validation failed: {e}")
        return 1

    # Create injector
    try:
        injector = create_injector(args.payload, config.__dict__, args.custom_file)
    except Exception as e:
        print(f"Error creating injector: {e}")
        return 1

    # Get targets
    targets = safety_config.targets

    shutdown = ShutdownCoordinator(verbose=config.logging.verbose)
    shutdown.install_handlers()

    iptables = IptablesManager(
        queue_num=config.network.queue_num,
        interface=config.network.interface,
        verbose=config.logging.verbose,
    )
    shutdown.register(iptables.remove_rules)
    if args.setup_iptables and not iptables.install_rules():
        print("Warning: could not install all iptables rules (root/Linux required)")

    arp_spoofer = None

    # Auto-hook mode
    if args.auto_hook:
        try:
            beef_integration = None
            if config.beef.enabled:
                beef_integration = BeEFIntegration(
                    host=config.beef.host,
                    port=config.beef.port,
                    api_token=config.beef.api_token,
                    verbose=config.logging.verbose,
                )

            auto_hook = AutoHookAgent(
                interface=config.network.interface,
                gateway=config.network.gateway,
                subnet=args.subnet,
                verbose=config.logging.verbose,
            )

            auto_hook.run_auto_hook(injector, config, beef_integration)
            return 0

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 0
        except Exception as e:
            print(f"Error in auto-hook mode: {e}")
            return 1

    # ARP spoofing
    if args.arp_spoof:
        if not config.network.gateway:
            print("ARP spoofing requires --gateway argument")
            return 1

        try:
            arp_spoofer = ARPSpoofer(
                targets=targets,
                gateway=config.network.gateway,
                interface=config.network.interface,
                verbose=config.logging.verbose,
            )
            shutdown.register(arp_spoofer.cleanup)

            import threading

            arp_thread = threading.Thread(target=arp_spoofer.start, daemon=True)
            arp_thread.start()

        except Exception as e:
            print(f"Error starting ARP spoofer: {e}")
            return 1

    # BeEF monitoring
    beef_integration = None
    if config.beef.enabled:
        beef_integration = BeEFIntegration(
            host=config.beef.host,
            port=config.beef.port,
            api_token=config.beef.api_token,
            verbose=config.logging.verbose,
        )

        import threading

        beef_thread = threading.Thread(
            target=beef_integration.monitor_hooks, args=(config.beef.poll_interval,), daemon=True
        )
        beef_thread.start()

    # Start NFQUEUE loop
    try:
        nfqueue_loop = NFQueueLoop(
            injector=injector,
            config=config.injection,
            targets=targets,
            queue_num=config.network.queue_num,
            verbose=config.logging.verbose,
        )
        shutdown.register(nfqueue_loop.cleanup)

        nfqueue_loop.start()
        return 0

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 0
    except Exception as e:
        print(f"Error in NFQUEUE loop: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
