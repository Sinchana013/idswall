"""
Root runner for simple_idps offline simulation demo.
Allows running `python demo.py` directly from workspace root.
"""

import importlib.util
from pathlib import Path
import sys

# Load demo module directly from simple_idps/demo.py
demo_path = Path(__file__).resolve().parent / "simple_idps" / "demo.py"
spec = importlib.util.spec_from_file_location("simple_idps.demo", str(demo_path))
if spec is None or spec.loader is None:
    raise ImportError(f"Cannot load demo from {demo_path}")
demo_module = importlib.util.module_from_spec(spec)
sys.modules["simple_idps.demo"] = demo_module
spec.loader.exec_module(demo_module)

if __name__ == "__main__":
    success = demo_module.run_demo()
    sys.exit(0 if success else 1)
