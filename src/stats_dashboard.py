"""
Statistics dashboard for XSS Code Injection tool.

This module provides a real-time dashboard showing injection statistics,
hooked browsers, and per-target status.
"""

import time
import threading
from typing import Dict, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class TargetStats:
    """Statistics for a specific target."""
    ip: str
    packets_processed: int = 0
    injections_attempted: int = 0
    successful_injections: int = 0
    last_injection: Optional[datetime] = None
    hooked: bool = False
    hook_time: Optional[datetime] = None


@dataclass
class GlobalStats:
    """Global statistics across all targets."""
    start_time: datetime = field(default_factory=datetime.now)
    packets_processed: int = 0
    http_responses_seen: int = 0
    injection_attempts: int = 0
    successful_injections: int = 0
    skipped_responses: int = 0
    chunked_responses: int = 0
    content_length_errors: int = 0
    total_hooks: int = 0


class StatsDashboard:
    """
    Real-time statistics dashboard.
    
    This class tracks and displays statistics for injection operations,
    including per-target metrics and global counts.
    """
    
    def __init__(self, update_interval: int = 1, verbose: bool = False):
        """
        Initialize the stats dashboard.
        
        Args:
            update_interval: Seconds between dashboard updates
            verbose: Enable verbose output
        """
        self.update_interval = update_interval
        self.verbose = verbose
        
        self.global_stats = GlobalStats()
        self.target_stats: Dict[str, TargetStats] = {}
        self.running = False
        self.display_thread: Optional[threading.Thread] = None
    
    def add_target(self, ip: str) -> None:
        """
        Add a target to track.
        
        Args:
            ip: Target IP address
        """
        if ip not in self.target_stats:
            self.target_stats[ip] = TargetStats(ip=ip)
    
    def update_packet_count(self, ip: str) -> None:
        """
        Update packet count for a target.
        
        Args:
            ip: Target IP address
        """
        self.global_stats.packets_processed += 1
        if ip in self.target_stats:
            self.target_stats[ip].packets_processed += 1
    
    def update_injection_attempt(self, ip: str) -> None:
        """
        Update injection attempt count for a target.
        
        Args:
            ip: Target IP address
        """
        self.global_stats.injection_attempts += 1
        if ip in self.target_stats:
            self.target_stats[ip].injections_attempted += 1
    
    def update_successful_injection(self, ip: str) -> None:
        """
        Update successful injection count for a target.
        
        Args:
            ip: Target IP address
        """
        self.global_stats.successful_injections += 1
        if ip in self.target_stats:
            self.target_stats[ip].successful_injections += 1
            self.target_stats[ip].last_injection = datetime.now()
    
    def update_hook_event(self, ip: str) -> None:
        """
        Update hook event for a target.
        
        Args:
            ip: Target IP address
        """
        self.global_stats.total_hooks += 1
        if ip in self.target_stats:
            self.target_stats[ip].hooked = True
            self.target_stats[ip].hook_time = datetime.now()
    
    def get_stats(self) -> tuple:
        """
        Get current statistics.
        
        Returns:
            Tuple of (global_stats, target_stats)
        """
        return self.global_stats, self.target_stats
    
    def display(self) -> None:
        """Display the current statistics dashboard."""
        while self.running:
            self._print_dashboard()
            time.sleep(self.update_interval)
    
    def _print_dashboard(self) -> None:
        """Print the dashboard to console."""
        # Clear screen (platform-specific)
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Calculate uptime
        uptime = datetime.now() - self.global_stats.start_time
        uptime_str = str(uptime).split('.')[0]
        
        # Print header
        print("=" * 70)
        print("XSS Code Injection - Statistics Dashboard")
        print("=" * 70)
        print(f"Uptime: {uptime_str}")
        print()
        
        # Print global stats
        print("📊 Global Statistics:")
        print(f"  Packets Processed:     {self.global_stats.packets_processed}")
        print(f"  HTTP Responses Seen:   {self.global_stats.http_responses_seen}")
        print(f"  Injection Attempts:    {self.global_stats.injection_attempts}")
        print(f"  Successful Injections: {self.global_stats.successful_injections}")
        print(f"  Skipped Responses:     {self.global_stats.skipped_responses}")
        print(f"  Chunked Responses:     {self.global_stats.chunked_responses}")
        print(f"  Content-Length Errors: {self.global_stats.content_length_errors}")
        print(f"  Total Hooks:           {self.global_stats.total_hooks}")
        print()
        
        # Calculate success rate
        if self.global_stats.injection_attempts > 0:
            success_rate = (
                self.global_stats.successful_injections / 
                self.global_stats.injection_attempts * 100
            )
            print(f"  Success Rate:          {success_rate:.1f}%")
        print()
        
        # Print per-target stats
        print("🎯 Per-Target Statistics:")
        if self.target_stats:
            for ip, stats in self.target_stats.items():
                hook_status = "✓ HOOKED" if stats.hooked else "○ Not Hooked"
                print(f"\n  Target: {ip}")
                print(f"    Status:           {hook_status}")
                print(f"    Packets:          {stats.packets_processed}")
                print(f"    Injections:       {stats.injections_attempted}")
                print(f"    Successful:       {stats.successful_injections}")
                if stats.last_injection:
                    print(f"    Last Injection:   {stats.last_injection.strftime('%H:%M:%S')}")
                if stats.hook_time:
                    print(f"    Hook Time:        {stats.hook_time.strftime('%H:%M:%S')}")
        else:
            print("  No targets being tracked")
        print()
        
        # Print footer
        print("=" * 70)
        print("Press Ctrl+C to stop")
        print("=" * 70)
    
    def start(self) -> None:
        """Start the dashboard display thread."""
        self.running = True
        self.display_thread = threading.Thread(target=self.display, daemon=True)
        self.display_thread.start()
    
    def stop(self) -> None:
        """Stop the dashboard."""
        self.running = False
        if self.display_thread:
            self.display_thread.join(timeout=2)
    
    def print_summary(self) -> None:
        """Print a one-time summary of statistics."""
        print("\n=== Final Statistics ===")
        print(f"Total packets processed: {self.global_stats.packets_processed}")
        print(f"Total injection attempts: {self.global_stats.injection_attempts}")
        print(f"Successful injections: {self.global_stats.successful_injections}")
        print(f"Total hooks: {self.global_stats.total_hooks}")
        
        if self.target_stats:
            print("\nPer-target summary:")
            for ip, stats in self.target_stats.items():
                print(f"  {ip}: {stats.successful_injections}/{stats.injections_attempted} injections")
