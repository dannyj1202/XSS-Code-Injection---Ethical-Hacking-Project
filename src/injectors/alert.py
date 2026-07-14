"""
Alert test injector.

This injector generates a simple JavaScript alert for testing purposes.
It's a benign payload that demonstrates injection without any security impact.
"""


from .base import BaseInjector


class AlertTestInjector(BaseInjector):
    """
    Injector that generates a simple JavaScript alert.

    This is a benign test payload that displays an alert dialog
    when the page loads. Useful for verifying injection works.
    """

    def __init__(self, config: dict | None = None):
        """
        Initialize the alert test injector.

        Args:
            config: Optional configuration dict with 'message' for alert text
        """
        super().__init__(config)
        self.message = self.config.get("message", "XSS Code Injection Test")

    def get_payload(self) -> str:
        """
        Generate the alert script.

        Returns:
            Script tag with alert() call
        """
        # Escape the message for JavaScript
        escaped_message = self.message.replace("'", "\\'").replace('"', '\\"')
        return f'<script>alert("{escaped_message}");</script>'

    def should_inject(self, html_content: str) -> bool:
        """
        Check if injection should occur.

        Args:
            html_content: HTML content to check

        Returns:
            True if </body> tag is present
        """
        return "</body>" in html_content
