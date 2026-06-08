"""Make the example package importable when pytest runs its tests.

The example is not installed; inserting its directory on ``sys.path`` lets
``import witseal_grc`` resolve when the suite is collected from the repo root.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
