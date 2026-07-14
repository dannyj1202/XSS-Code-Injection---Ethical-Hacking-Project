"""
BeEF integration module.

This module provides integration with the Browser Exploitation Framework (BeEF)
to detect hooked browsers and close the loop between injection and BeEF.
"""

import json
import time
from typing import Optional, Dict, List, Set
from dataclasses import dataclass
from datetime import datetime
import requests


@dataclass
class HookedBrowser:
    """Information about a hooked browser."""
    session_id: str
    ip: str
    hostname: str
    os: str
    browser: str
    first_seen: datetime
    last_seen: datetime


class BeEFIntegration:
    """
    Integration with BeEF REST API.
    
    This class connects to a BeEF server, monitors for hooked browsers,
    and provides real-time notifications when new hooks are detected.
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3000,
        api_token: Optional[str] = None,
        verbose: bool = False
    ):
        """
        Initialize BeEF integration.
        
        Args:
            host: BeEF server host
            port: BeEF server port
            api_token: BeEF REST API token
            verbose: Enable verbose logging
        """
        self.host = host
        self.port = port
        self.api_token = api_token
        self.verbose = verbose
        
        self.base_url = f"http://{host}:{port}/api"
        self.hooked_browsers: Dict[str, HookedBrowser] = {}
        self.known_session_ids: Set[str] = set()
        
        self.running = False
    
    def _get_headers(self) -> Dict[str, str]:
        """
        Get headers for API requests.
        
        Returns:
            Dictionary with authentication headers
        """
        if self.api_token:
            return {
                'Authorization': f'Token {self.api_token}',
                'Content-Type': 'application/json'
            }
        return {'Content-Type': 'application/json'}
    
    def _api_request(self, endpoint: str, method: str = 'GET') -> Optional[dict]:
        """
        Make a request to the BeEF API.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST, etc.)
            
        Returns:
            JSON response as dict, or None on error
        """
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=self._get_headers(), timeout=5)
            else:
                response = requests.post(url, headers=self._get_headers(), timeout=5)
            
            if response.status_code == 200:
                return response.json()
            else:
                if self.verbose:
                    print(f"API request failed: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"Error connecting to BeEF API: {e}")
            return None
    
    def get_online_browsers(self) -> List[HookedBrowser]:
        """
        Get list of currently online hooked browsers.
        
        Returns:
            List of HookedBrowser objects
        """
        data = self._api_request('hooks', 'GET')
        
        if not data or 'hooks' not in data:
            return []
        
        browsers = []
        
        for hook_id, hook_data in data['hooks'].items():
            try:
                browser = HookedBrowser(
                    session_id=hook_id,
                    ip=hook_data.get('ip', 'unknown'),
                    hostname=hook_data.get('hostname', 'unknown'),
                    os=hook_data.get('os', 'unknown'),
                    browser=hook_data.get('browser', 'unknown'),
                    first_seen=datetime.fromtimestamp(hook_data.get('first_seen', 0)),
                    last_seen=datetime.fromtimestamp(hook_data.get('last_seen', 0))
                )
                browsers.append(browser)
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing hook data: {e}")
                continue
        
        return browsers
    
    def check_new_hooks(self) -> List[HookedBrowser]:
        """
        Check for newly hooked browsers since last check.
        
        Returns:
            List of newly hooked browsers
        """
        current_browsers = self.get_online_browsers()
        new_hooks = []
        
        for browser in current_browsers:
            if browser.session_id not in self.known_session_ids:
                new_hooks.append(browser)
                self.known_session_ids.add(browser.session_id)
            
            self.hooked_browsers[browser.session_id] = browser
        
        return new_hooks
    
    def monitor_hooks(self, poll_interval: int = 5) -> None:
        """
        Continuously monitor for new hooked browsers.
        
        Args:
            poll_interval: Seconds between API polls
        """
        self.running = True
        
        if self.verbose:
            print(f"Starting BeEF hook monitoring (polling every {poll_interval}s)...")
        
        try:
            while self.running:
                new_hooks = self.check_new_hooks()
                
                for hook in new_hooks:
                    self._print_hook_event(hook)
                
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            if self.verbose:
                print("\nStopping BeEF monitoring...")
            self.running = False
    
    def _print_hook_event(self, hook: HookedBrowser) -> None:
        """
        Print a hook event to console.
        
        Args:
            hook: HookedBrowser object
        """
        print("\n" + "="*60)
        print("🎯 NEW BROWSER HOOKED!")
        print("="*60)
        print(f"Session ID: {hook.session_id}")
        print(f"IP Address: {hook.ip}")
        print(f"Hostname: {hook.hostname}")
        print(f"OS: {hook.os}")
        print(f"Browser: {hook.browser}")
        print(f"First Seen: {hook.first_seen}")
        print("="*60 + "\n")
    
    def stop(self) -> None:
        """Stop monitoring hooks."""
        self.running = False
    
    def get_hook_count(self) -> int:
        """
        Get total number of hooked browsers.
        
        Returns:
            Number of hooked browsers
        """
        return len(self.hooked_browsers)
    
    def get_hook_summary(self) -> str:
        """
        Get a summary of hooked browsers.
        
        Returns:
            Formatted summary string
        """
        if not self.hooked_browsers:
            return "No browsers currently hooked"
        
        summary = f"Total hooked browsers: {len(self.hooked_browsers)}\n"
        
        for session_id, hook in self.hooked_browsers.items():
            summary += f"  - {hook.ip} ({hook.browser} on {hook.os})\n"
        
        return summary
