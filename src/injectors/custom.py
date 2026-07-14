"""
Custom JavaScript injector.

This injector loads JavaScript code from a file for custom payloads.
"""

from pathlib import Path
from typing import Optional
from .base import BaseInjector


class CustomJSInjector(BaseInjector):
    """
    Injector that loads custom JavaScript from a file.
    
    This allows users to provide their own JavaScript payloads
    from a file for custom testing scenarios.
    """
    
    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the custom JS injector.
        
        Args:
            config: Configuration dict with 'file_path' for the JS file
        """
        super().__init__(config)
        self.file_path = self.config.get('file_path')
        self.payload = None
        
        if self.file_path:
            self._load_payload()
    
    def _load_payload(self) -> None:
        """
        Load JavaScript from the specified file.
        
        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If the file can't be read
        """
        if not self.file_path:
            return
        
        path = Path(self.file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Custom JS file not found: {self.file_path}")
        
        with open(path, 'r') as f:
            js_content = f.read()
        
        # Wrap in script tags if not already present
        if not js_content.strip().startswith('<script'):
            self.payload = f'<script>{js_content}</script>'
        else:
            self.payload = js_content
    
    def get_payload(self) -> str:
        """
        Get the custom JavaScript payload.
        
        Returns:
            Script tag with custom JavaScript content
            
        Raises:
            ValueError: If no file was loaded
        """
        if not self.payload:
            raise ValueError(
                "No custom JS loaded. Provide 'file_path' in config."
            )
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
