"""Install a project-local kernel pointing to the CLI interpreter."""

import sys
from pathlib import Path

from ipykernel.kernelspec import install

root = Path(__file__).resolve().parents[1]
if Path(sys.prefix).resolve() != (root / ".venv").resolve():
    raise SystemExit("Run with uv run --all-groups python scripts/setup_notebook_kernel.py")
install(
    kernel_name="ids-ml-detection-lab",
    display_name="Python (ids-ml-detection-lab)",
    prefix=str(root / ".venv"),
)
print(f"Notebook and CLI Python: {sys.executable}")
