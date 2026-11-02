"""Shared paths for the tests; importing it puts the tool's modules on sys.path."""
import os
import shutil
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(TESTS)
REPO = os.path.dirname(os.path.dirname(TOOL))
DATA = os.path.join(TESTS, "data")
BASELINE = os.path.join(TOOL, "baseline")

sys.path.insert(0, TOOL)

needs_tshark = unittest.skipIf(shutil.which("tshark") is None, "tshark is not installed")
