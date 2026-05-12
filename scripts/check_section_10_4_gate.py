#!/usr/bin/env python3
"""Wrapper entrypoint for the section 10.4 gate (bd-261k)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

from gate_section_10_4 import main
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


if __name__ == "__main__":
    logger = configure_test_logging("check_section_10_4_gate")
    logger.info("starting section 10.4 gate wrapper")
    main()
