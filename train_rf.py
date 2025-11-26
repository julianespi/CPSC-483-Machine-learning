#!/usr/bin/env python3
"""
train_rf.py

Train a RandomForest classifier on the RT_IOT2022_processed.csv dataset
using ONLY the features that live_capture.py can compute in real time.

Target:
    Attack_type  (e.g., DOS_SYN_Hping, DDOS_Slowloris, NMAP_UDP_SCAN, ...)

Features used (must match live_capture.py):
    - Basic flow stats: duration, pkts, bytes, rates, ratio
    - Categorical: proto, service
    - Payload stats: fwd/bwd payload avg, payload_bytes_per_second
    - TCP flags: SYN/FIN/RST/ACK/etc.
    - IAT stats: fwd_iat.*, bwd_iat.*, flow_iat.*

Output:
    models/attack_detector_rf.joblib
        {
          "pipeline": sklearn Pipeline,
          "feature_columns": [...],
          "target_col": "Attack_type",
        }

Usage:
    python3 train_rf.py

NOTE:
    If your CSV is under data/, change CSV_PATH below to:
        CSV_PATH = Path("data/RT_IOT2022_processed.csv")
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# === CONFIG ===

# Adjust this if your CSV lives in data/ instead:
# CSV_PATH = Path("data/RT_IOT2022_processed.csv")
CSV_PATH = Path("data/RT_IOT2022_processed.csv")

MODEL_OUT = Path("models/attack_detector_rf.joblib")
TARGET_COL = "Attack_type"
RANDOM_STATE = 42
TEST_SIZE = 0.2

# === Features that live_capture.py can compute & send ===
ONLINE_FEATURES = [
    # Categorical
    "proto",
    "service",

    # Flow-level basic stats
    "flow_duration",
    "fwd_pkts_tot",
    "bwd_pkts_tot",
    "fwd_data_pkts_tot",
    "bwd_data_pkts_tot",
    "fwd_pkts_per_sec",
    "bwd_pkts_per_sec",
    "flow_pkts_per_sec",
    "down_up_ratio",

    # Payload-related (what we fill in live_capture)
    "fwd_pkts_payload.avg",
    "bwd_pkts_payload.avg",
    "payload_bytes_per_second",

    # TCP flag counters (we added in live_capture)
    "flow_FIN_flag_count",
    "flow_SYN_flag_count",
    "flow_RST_flag_count",
    "flow_ACK_flag_count",
    "flow_CWR_flag_count",
    "flow_ECE_flag_count",
    "fwd_PSH_flag_count",
    "bwd_PSH_flag_count",
    "fwd_URG_flag_count",
    "bwd_URG_flag_count",

    # IAT stats (we added in live_capture)
    "fwd_iat.min",
    "fwd_iat.max",
    "fwd_iat.tot",
    "fwd_iat.avg",
    "fwd_iat.std",
    "bwd_iat.min",
    "bwd_iat.max",
    "bwd_iat.tot",
    "bwd_iat.avg",
    "bwd_iat.std",
    "flow_iat.min",
    "flow_iat.max",
    "flow_iat.tot",
    "flow_iat.avg",
    "flow_iat.std",
]


def main() -> None:
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Could not find dataset at {CSV_PATH.resolve()}")

    print(f"[train_rf] Loading dataset from {CSV_PATH.resolve()}")
    df = pd.read_csv(CSV_PATH)

    if TARGET_COL not in df.columns:
        raise RuntimeError(f"Expected target column '{TARGET_COL}' not found in CSV.")

    # Ensure all ONLINE_FEATURES exist in the CSV
    missing = [c for c in ONLINE_FEATURES if c not in df.columns]
    if missing:
        raise RuntimeError(
            f"The following ONLINE_FEATURES are missing from the CSV: {missing}"
        )

    # Separate features and target
    X = df[ONLINE_FEATURES].copy()
    y = df[TARGET_COL].astype(str)

    print(f"[train_rf] Dataset shape: X={X.shape}, y={y.shape}")
    print(f"[train_rf] Unique classes (Attack_type): {sorted(y.unique())}")

    # Categorical vs numeric
    categorical_cols = [c for c in ["proto", "service"] if c in X.columns]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]

    print(f"[train_rf] Using {len(numeric_cols)} numeric features")
    print(f"[train_rf] Using categorical features: {categorical_cols}")

    numeric_transformer = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols),
        ],
        remainder="drop",
    )

    clf = RandomForestClassifier(
        n_estimators=400,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        max_depth=None,
        class_weight=None,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("clf", clf),
        ]
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"[train_rf] Training set: {X_train.shape}, Test set: {X_test.shape}")
    print("[train_rf] Fitting pipeline...")
    pipeline.fit(X_train, y_train)

    print("[train_rf] Evaluating on held-out test set...")
    y_pred = pipeline.predict(X_test)

    print("=== Classification report ===")
    try:
        print(classification_report(y_test, y_pred))
    except Exception as e:
        print("Error printing classification report:", e)

    print("=== Confusion matrix ===")
    try:
        print(confusion_matrix(y_test, y_pred))
    except Exception as e:
        print("Error printing confusion matrix:", e)

    # Ensure models directory exists
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "pipeline": pipeline,
        "feature_columns": ONLINE_FEATURES,
        "target_col": TARGET_COL,
    }

    joblib.dump(bundle, MODEL_OUT)
    print(f"[train_rf] Saved model bundle to {MODEL_OUT.resolve()}")


if __name__ == "__main__":
    main()