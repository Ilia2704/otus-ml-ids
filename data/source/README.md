# Dataset provenance

The included `kddcup.data_10_percent.gz` is the public 10% KDD Cup 1999 network-intrusion dataset.

- Canonical record: [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/130/kdd+cup+1999+data)
- DOI: [10.24432/C51C7N](https://doi.org/10.24432/C51C7N)
- Authors: Salvatore Stolfo, Wei Fan, Wenke Lee, Andreas Prodromidis, Philip Chan
- License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Included source file SHA-256: `8045aca0d84e70e622d1148d7df782496f6333bf6eb979a1b0837c42a9fd9561`
- Verified mirror used by scikit-learn: `https://ndownloader.figshare.com/files/5976042`

## Preparation

`uv run ids-build-data` verifies the source checksum, keeps the 16 columns used by the lab, removes duplicate rows, creates a deterministic balanced sample of 24,000 rows, and writes stratified 60/20/20 train/validation/test Parquet files. Exact output checksums and class counts are stored in `data/prepared/dataset_info.json`.

The model is fit only on normal rows from the training split. Labels are used for validation, threshold selection, and final evaluation—not to fit Isolation Forest.

## Important limitations

KDD Cup 1999 is old, heavily synthetic, and contains redundancy and artifacts that do not represent modern enterprise traffic. It is included because it is small, public, licensed, checksum-verifiable, and practical for a classroom. Results must not be presented as evidence of production IDS quality.

The live Zeek feature adapter intentionally exposes offline/online feature mismatch. Replacing this dataset with a modern organization-specific feature store, adding drift monitoring, and defining a stable feature contract are natural lecture 4–5 extensions.
