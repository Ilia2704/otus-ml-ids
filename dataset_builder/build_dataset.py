from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from dataset_builder.schema import FEATURES, KDD_COLUMNS

SOURCE_SHA256 = "8045aca0d84e70e622d1148d7df782496f6333bf6eb979a1b0837c42a9fd9561"
SEED = 42


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _balanced_sample(frame: pd.DataFrame, rows: int, seed: int) -> pd.DataFrame:
    per_class = rows // 2
    normal = frame[frame["label"] == 0].sample(n=per_class, random_state=seed)
    attacks = frame[frame["label"] == 1].sample(n=rows - per_class, random_state=seed)
    return pd.concat([normal, attacks]).sample(frac=1, random_state=seed).reset_index(drop=True)


def build(source: Path, output_dir: Path, rows: int = 24_000, seed: int = SEED) -> None:
    if sha256(source) != SOURCE_SHA256:
        raise ValueError(
            f"Unexpected SHA-256 for {source}; refusing to build from unverified input"
        )

    frame = pd.read_csv(source, compression="gzip", names=KDD_COLUMNS, low_memory=False)
    frame["attack_type"] = frame["attack_type"].str.rstrip(".")
    frame["label"] = (frame["attack_type"] != "normal").astype("int8")
    frame = frame[FEATURES + ["label", "attack_type"]].drop_duplicates().reset_index(drop=True)
    if rows > len(frame):
        raise ValueError(f"Requested {rows} rows, but only {len(frame)} unique rows are available")

    sample = _balanced_sample(frame, rows=rows, seed=seed)
    train, holdout = train_test_split(
        sample, test_size=0.4, random_state=seed, stratify=sample["label"]
    )
    validation, test = train_test_split(
        holdout, test_size=0.5, random_state=seed, stratify=holdout["label"]
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    splits = {"train": train, "validation": validation, "test": test}
    files: dict[str, dict[str, object]] = {}
    for name, split in splits.items():
        path = output_dir / f"{name}.parquet"
        split.reset_index(drop=True).to_parquet(path, index=False, compression="zstd")
        files[path.name] = {
            "rows": len(split),
            "normal": int((split["label"] == 0).sum()),
            "attack": int((split["label"] == 1).sum()),
            "sha256": sha256(path),
        }

    info = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source": "UCI KDD Cup 1999, 10% subset",
        "source_doi": "10.24432/C51C7N",
        "source_url": "https://archive.ics.uci.edu/dataset/130/kdd+cup+1999+data",
        "source_mirror": "https://ndownloader.figshare.com/files/5976042",
        "source_sha256": SOURCE_SHA256,
        "license": "CC BY 4.0",
        "seed": seed,
        "selection": "deduplicated, balanced binary sample; 60/20/20 stratified split",
        "features": FEATURES,
        "target": "label (0=normal, 1=attack)",
        "files": files,
    }
    (output_dir / "dataset_info.json").write_text(
        json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Build deterministic KDD Cup 1999 teaching splits")
    parser.add_argument(
        "--source", type=Path, default=root / "data/source/kddcup.data_10_percent.gz"
    )
    parser.add_argument("--output-dir", type=Path, default=root / "data/prepared")
    parser.add_argument("--rows", type=int, default=24_000)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    build(args.source, args.output_dir, rows=args.rows, seed=args.seed)
    print(f"Prepared dataset written to {args.output_dir}")


if __name__ == "__main__":
    main()
