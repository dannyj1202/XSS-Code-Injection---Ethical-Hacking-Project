"""
Base class for injection strategies.

All injectors must inherit from BaseInjector and implement the get_payload method.
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseInjector(ABC):
    """
    Abstract base class for injection strategies.
    
    This class defines the interface that all injection strategies must implement.
    Subclasses should provide specific payload generation logic.
    """
    
    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the injector.
        
        Args:
            config: Optional configuration dictionary for the injector
        """
        self.config = config or {}
        self.name = self.__class__.__name__
    
    @abstractmethod
    def get_payload(self) -> str:
        """
        Generate the JavaScript payload to inject.
        
        Returns:
            JavaScript code as a string (typically wrapped in <script> tags)
        """
        pass
    
    def get_injection_point(self) -> str:
        """
        Get the injection point marker.
        
        Returns:
            String to search for in the HTML (default: "</body>")
        """
        return "</body>"
    
    def should_inject(self, html_content: str) -> bool:
        """
        Determine if injection should occur for this content.
        
        Args:
            html_content: The HTML content to check
            
        Returns:
            True if injection should proceed, False otherwise
        """
        # Default: inject if the injection point exists
        return self.get_injection_point() in html_content
    
    def validate_payload(self, payload: str) -> bool:
        """
        Validate the generated payload.
        
        Args:
            payload: The payload to validate
            
        Returns:
            True if payload is valid, False otherwise
        """
        return bool(payload) and isinstance(payload, str)
    
    def __repr__(self) -> str:
        """String representation of the injector."""
        return f"{self.name}(config={self.config})"
