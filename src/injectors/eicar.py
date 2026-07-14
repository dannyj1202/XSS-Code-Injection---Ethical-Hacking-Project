"""
EICAR test string injector.

This injector uses the standard EICAR test string for antivirus testing.
It's the default safe payload for demonstrating injection without actual malware.
"""

from typing import Optional

from ..config.safety import EICAR_TEST_STRING
from .base import BaseInjector


class EicarTestInjector(BaseInjector):
    """
    Injector that uses the EICAR test string.

    The EICAR test string is a standard antivirus test file that is detected
    by all antivirus software but is completely harmless. This is the default
    payload for safe, educational demonstrations.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the EICAR injector.

        Args:
            config: Optional configuration (not used for EICAR)
        """
        super().__init__(config)
        self.payload = self._generate_payload()

    def _generate_payload(self) -> str:
        """
        Generate the EICAR payload wrapped in a script tag.

        Returns:
            Script tag with EICAR test string as a JavaScript comment
        """
        # Embed EICAR as a JavaScript comment - harmless but detectable
        return f'<script>/* {EICAR_TEST_STRING} */ console.log("EICAR test payload injected");</script>'

    def get_payload(self) -> str:
        """
        Get the EICAR payload.

        Returns:
            Script tag with EICAR test string
        """
        return self.payload

    def should_inject(self, html_content: str) -> bool:
        """
        Check if injection should occur.

        Args:
            html_content: HTML content to check

        Returns:
            True if </body> tag is present
        """
        return "</body>" in html_content
