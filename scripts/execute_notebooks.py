"""Execute both demos in fresh kernels and preserve partial output on failure."""

import argparse
import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument(
    "notebooks", nargs="*", default=["01_train_validate_explain.ipynb", "02_isolation_forest.ipynb"]
)
args = parser.parse_args()
if Path(sys.prefix).resolve() != (root / ".venv").resolve():
    raise SystemExit("Use the project .venv Python")
for name in args.notebooks:
    path = root / "notebooks" / name
    notebook = nbformat.read(path, as_version=4)

    def progress(cell, cell_index, notebook_name=name, **kwargs):
        if cell.cell_type == "code":
            print(f"{notebook_name}: cell {cell_index}: {cell.source.splitlines()[0]}", flush=True)

    client = NotebookClient(
        notebook,
        timeout=1800,
        kernel_name="ids-ml-detection-lab",
        resources={"metadata": {"path": str(root)}},
        on_cell_start=progress,
    )
    try:
        client.execute()
    except Exception:
        output = root / ".notebook-diagnostics" / name
        output.parent.mkdir(exist_ok=True)
        nbformat.write(notebook, output)
        print(f"Partial results: {output}", flush=True)
        raise
    nbformat.write(notebook, path)
    print(f"{name}: completed", flush=True)
