"""
Simple IDPS - Beginner-Friendly Intrusion Detection & Prevention System
"""

from .detector import Detector
from .firewall import FirewallController

__all__ = ["Detector", "FirewallController"]
