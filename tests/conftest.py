"""
Pytest configuration file.

Sets up the Python path and optional netfilterqueue stub for non-Linux hosts.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

if "netfilterqueue" not in sys.modules:
    nfq_stub = MagicMock()
    nfq_stub.NetfilterQueue = MagicMock
    nfq_stub.Packet = object
    sys.modules["netfilterqueue"] = nfq_stub
