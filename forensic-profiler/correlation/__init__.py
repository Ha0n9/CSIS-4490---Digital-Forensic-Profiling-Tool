#!/usr/bin/env python3
"""
Correlation Package - Connect artifacts and detect patterns
"""

from .engine import CorrelationEngine
from .narrative import build_narrative

__all__ = ['CorrelationEngine', 'build_narrative']
