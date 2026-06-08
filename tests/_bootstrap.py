"""Put ``src/`` on ``sys.path`` so the suite runs from a bare checkout.

``pyproject.toml`` adds ``src/`` for ``pytest`` via ``pythonpath = ["src"]``.
When the suite is run with the standard-library runner instead
(``python3 -m unittest discover -s tests``) there is no such hook, so importing
this module from a test file makes ``import alertward`` work with no editable
install and no third-party dependencies. Under ``pytest`` the path is already
present, so the insertion is a harmless no-op.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
