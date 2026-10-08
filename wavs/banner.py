from __future__ import annotations

import sys
from typing import TextIO

from wavs import __version__

_ART = r"""
__        _____     ______
\ \      / / \ \   / / ___|
 \ \ /\ / / _ \ \ / /\___ \
  \ V  V / ___ \ V /  ___) |
   \_/\_/_/   \_\_/  |____/
"""


def banner() -> str:
    return (
        f"{_ART}\n"
        f"  Web Application Vulnerability Scanner  v{__version__}\n"
        "  Educational use only - run against authorised targets.\n"
    )


def print_banner(stream: TextIO = sys.stderr) -> None:
    print(banner(), file=stream)
