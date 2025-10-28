"""
Adapter templates for integrating external agents.
"""

from .base_adapter import BaseAdapter
from .rest_adapter import RESTAdapter
from .message_adapter import MessageQueueAdapter
from .cli_adapter import CLIAdapter

__all__ = ['BaseAdapter', 'RESTAdapter', 'MessageQueueAdapter', 'CLIAdapter']
