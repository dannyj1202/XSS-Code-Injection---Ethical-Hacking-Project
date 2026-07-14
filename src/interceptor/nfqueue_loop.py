"""
NFQUEUE loop for network packet interception.

This module manages the NetfilterQueue loop that intercepts packets
and passes them to the packet handler for processing.
"""

import signal
import sys
from typing import Optional, Set

from netfilterqueue import NetfilterQueue

from .packet_handler import PacketHandler
from ..injectors.base import BaseInjector
from ..config.settings import InjectionConfig


class NFQueueLoop:
    """
    Manager for the NetfilterQueue packet interception loop.
    
    This class handles the NFQUEUE setup, packet processing loop,
    and graceful shutdown on SIGINT.
    """
    
    def __init__(
        self,
        injector: BaseInjector,
        config: InjectionConfig,
        targets: Set[str],
        queue_num: int = 0,
        verbose: bool = False
    ):
        """
        Initialize the NFQUEUE loop.
        
        Args:
            injector: The injection strategy to use
            config: Injection configuration
            targets: Set of allowed target IP addresses
            queue_num: NFQUEUE number (default: 0)
            verbose: Enable verbose logging
        """
        self.injector = injector
        self.config = config
        self.targets = targets
        self.queue_num = queue_num
        self.verbose = verbose
        
        self.packet_handler = PacketHandler(
            injector=injector,
            config=config,
            targets=targets,
            verbose=verbose
        )
        
        self.nfq: Optional[NetfilterQueue] = None
        self.running = False
    
    def setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame) -> None:
        """
        Handle shutdown signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if self.verbose:
            print(f"\nReceived signal {signum}, shutting down...")
        self.running = False
    
    def start(self) -> None:
        """
        Start the NFQUEUE loop.
        
        This method blocks until the loop is stopped.
        """
        self.running = True
        self.setup_signal_handlers()
        
        try:
            # Create NetfilterQueue instance
            self.nfq = NetfilterQueue()
            
            # Bind to queue
            self.nfq.bind(self.queue_num, self._process_packet)
            
            if self.verbose:
                print(f"NFQUEUE loop started on queue {self.queue_num}")
                print(f"Monitoring targets: {', '.join(self.targets)}")
                print(f"Injector: {self.injector.name}")
                print("Press Ctrl+C to stop...")
            
            # Run the loop
            self.nfq.run()
            
        except Exception as e:
            print(f"Error in NFQUEUE loop: {e}")
            raise
        finally:
            self.cleanup()
    
    def _process_packet(self, packet) -> None:
        """
        Process a single packet from the queue.
        
        Args:
            packet: NetfilterQueue packet object
        """
        if not self.running:
            packet.accept()
            return
        
        self.packet_handler.handle_packet(packet)
    
    def stop(self) -> None:
        """Stop the NFQUEUE loop."""
        self.running = False
        
        if self.nfq:
            self.nfq.unbind()
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        if self.nfq:
            try:
                self.nfq.unbind()
            except Exception:
                pass
        
        # Print statistics
        stats = self.packet_handler.get_stats()
        if self.verbose:
            print("\n=== Injection Statistics ===")
            print(f"Packets processed: {stats.packets_processed}")
            print(f"HTTP responses seen: {stats.http_responses_seen}")
            print(f"Injection attempts: {stats.injection_attempts}")
            print(f"Successful injections: {stats.successful_injections}")
            print(f"Skipped responses: {stats.skipped_responses}")
            print(f"Chunked responses: {stats.chunked_responses}")
            print(f"Content-Length errors: {stats.content_length_errors}")
    
    def get_stats(self):
        """
        Get current statistics.
        
        Returns:
            InjectionStats object
        """
        return self.packet_handler.get_stats()
