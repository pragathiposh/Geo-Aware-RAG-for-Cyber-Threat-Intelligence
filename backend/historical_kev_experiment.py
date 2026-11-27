import csv
import gzip
import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

ROOT = Path.cwd()
NVD_DIR = Path.home() / "nvd-feeds"
EPSS_DIR = Path.home() / "epss-feeds/historical"
OUTPUT_BASE = ROOT / "data/ml_experiments"
FEATURES = ["epss", "percentile", "age_days"]

def parse_date(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

print("Loading KEV listing dates...", flush=True)
with (ROOT / "data/processed/enriched_cves_final.json").open() as f:
    records = json.load(f)

kev = {
    r["cve_id"]: parse_date(r["cisa_date_added"])
    for r in records
    if r.get("cve_id") and r.get("cisa_date_added")
}

print("Loading NVD publication dates...", flush=True)
published = {}
feeds = sorted(NVD_DIR.glob("nvdcve-2.0-*.json.gz"))
if not feeds:
    raise RuntimeError("No NVD feeds found")

for path in feeds:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        feed = json.load(f)
    for item in feed.get("vulnerabilities", []):
        c = item.get("cve", {})
        if c.get("id") and c.get("published"):
            published[c["id"]] = parse_date(c["published"])
    del feed

print("NVD publication records:", len(published), flush=True)

# Each example is a (CVE, prediction-window) pair.
# Store all validation/test examples, and all training
# positives plus a reproducible 10% of training negatives.
datasets = {
    "train": {"X": [], "y": [], "epss": []},
    "validation": {"X": [], "y": [], "epss": []},
    "test": {"X": [], "y": [], "epss": []},
}
counts = Counter()
window_counts = []

for year in range(2022, 2026):
    for month in (1, 4, 7, 10):
        if year == 2022 and month == 1:
            print("Skipping 2022-01: snapshot date not verified")
            continue

        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=90)
        snapshot = (start - timedelta(days=1)).date().isoformat()
        path = EPSS_DIR / f"epss_scores-{snapshot}.csv.gz"

        split = (
            "train" if year <= 2023
            else "validation" if year == 2024
            else "test"
        )

        if not path.exists():
            raise FileNotFoundError(path)

        window_total = 0
        window_positive = 0

        with gzip.open(path, "rt", encoding="utf-8") as f:
            metadata = f.readline().strip()
            if not metadata.startswith("#"):
                raise ValueError(
                    f"Missing dated metadata: {path.name}"
                )
            if f"score_date:{snapshot}T" not in metadata:
                raise ValueError(
                    f"Snapshot date mismatch: {path.name}: {metadata}"
                )

            for row in csv.DictReader(f):
                cve_id = row["cve"].strip().upper()
                published_at = published.get(cve_id)

                if published_at is None or published_at >= start:
                    continue

                added = kev.get(cve_id)
                if added is not None and added < start:
                    continue

                label = int(
                    added is not None and start <= added < end
                )

                # Keep a deterministic subset of training negatives.
                # Validation and testing retain every eligible CVE
                # with a score in its historical EPSS snapshot.
                if split == "train" and not label:
                    token = f"{snapshot}:{cve_id}".encode()
                    bucket = int.from_bytes(
                        hashlib.sha256(token).digest()[:4],
                        "big",
                    ) % 10
                    if bucket != 0:
                        continue

                epss = float(row["epss"])
                percentile = float(row["percentile"])
                age_days = max(
                    0.0, (start - published_at).total_seconds() / 86400
                )

                datasets[split]["X"].append(
                    [epss, percentile, age_days]
                )
                datasets[split]["y"].append(label)
                datasets[split]["epss"].append(epss)

                window_total += 1
                window_positive += label

        counts[f"{split}_rows"] += window_total
        counts[f"{split}_positives"] += window_positive
        window_counts.append({
            "window": f"{year}-{month:02d}",
            "split": split,
            "rows": window_total,
            "positives": window_positive,
        })
        print(
            f"{year}-{month:02d} {split}: "
            f"{window_total:,} rows, {window_positive} positives",
            flush=True,
        )

print("\nTraining XGBoost...", flush=True)

train = datasets["train"]
X_train = np.asarray(train["X"], dtype=np.float32)
y_train = np.asarray(train["y"], dtype=np.int8)

if len(np.unique(y_train)) < 2:
    raise RuntimeError("Training split needs both classes")

model = XGBClassifier(
    n_estimators=150,
    max_depth=3,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=1.0,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    n_jobs=4,
    random_state=42,
)
model.fit(X_train, y_train)

def evaluate(y, scores):
    if len(y) == 0 or len(np.unique(y)) < 2:
        return {"error": "Both classes required"}

    k = min(100, len(y))
    order = np.argsort(-scores, kind="stable")[:k]
    hits = int(y[order].sum())
    positives = int(y.sum())

    return {
        "rows": int(len(y)),
        "positives": positives,
        "positive_prevalence": float(y.mean()),
        "average_precision": float(
            average_precision_score(y, scores)
        ),
        "roc_auc": float(roc_auc_score(y, scores)),
        "precision_at_100": float(hits / k),
        "recall_at_100": float(hits / positives),
    }

results = {}
for split in ("validation", "test"):
    data = datasets[split]
    X = np.asarray(data["X"], dtype=np.float32)
    y = np.asarray(data["y"], dtype=np.int8)
    epss = np.asarray(data["epss"], dtype=np.float32)

    predictions = model.predict_proba(X)[:, 1]

    results[split] = {
        "xgboost": evaluate(y, predictions),
        "epss_baseline": evaluate(y, epss),
    }

    print(f"\n{split.upper()} RESULTS")
    for name, metrics in results[split].items():
        print(name, json.dumps(metrics, indent=2))

# Create a new output directory; never overwrite an old run.
OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
run_name = datetime.now(timezone.utc).strftime(
    "kev90d_exploratory_%Y%m%d_%H%M%S_%f"
)
output_dir = OUTPUT_BASE / run_name
output_dir.mkdir(exist_ok=False)

model.save_model(str(output_dir / "xgboost_model.json"))

report = {
    "status": "EXPLORATORY_NOT_LEAKAGE_FREE",
    "feature_names": FEATURES,
    "training_negative_sample_fraction": 0.1,
    "train_rows": len(y_train),
    "train_positives": int(y_train.sum()),
    "window_counts": window_counts,
    "results": results,
    "limitations": [
        "NVD publication dates come from current, not historical, feeds",
        "Historical NVD rejection status is not reconstructed",
        "2022-01 excluded because EPSS snapshot lacks dated metadata",
        "Training negatives are deterministically sampled",
        "EPSS model versions vary between years",
        "Target is future KEV listing, not exploitation itself",
    ],
}
with (output_dir / "report.json").open("w") as f:
    json.dump(report, f, indent=2)

print("\nEXPERIMENT COMPLETE")
print("Saved to:", output_dir)
print("Existing risk modules were not modified.")
