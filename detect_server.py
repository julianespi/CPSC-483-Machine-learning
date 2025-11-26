#!/usr/bin/env python3
"""
detect_server.py

FastAPI server that loads the RandomForest model trained by train_rf.py
and exposes endpoints to classify network flows as specific attack types.

- On startup, loads models/attack_detector_rf.joblib.
- Uses RT_IOT2022_processed.csv header (or saved feature_columns) to know
  which feature columns to expect.
- /predict accepts a single feature dict, fills missing features with
  sensible defaults, and returns BOTH:
    * raw_prediction: the original Attack_type from the dataset
    * prediction: a nicer, human-readable label
- /predict_batch does the same for multiple instances.

Usage:
    uvicorn detect_server:app --host 0.0.0.0 --port 8000 --reload
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

MODEL_PATH = Path("models/attack_detector_rf.joblib")
CSV_PATH = Path("RT_IOT2022_processed.csv")  # used only for feature names

app = FastAPI(title="Attack Detector", version="1.1")


class PredictRequest(BaseModel):
    features: Dict[str, Any]


class PredictBatchRequest(BaseModel):
    instances: List[Dict[str, Any]]


# Global objects initialised at startup
pipeline = None
feature_columns: List[str] = []
target_col: str = "Attack_type"
default_values: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
#  Nice label mapping
# ---------------------------------------------------------------------------

RAW_LABEL_TO_NICE: Dict[str, str] = {
    # Benign / normal traffic
    "Thing_Speak": "Benign: ThingSpeak LED traffic",
    "Wipro_bulb": "Benign: Wipro smart bulb traffic",
    "Normal": "Benign: Normal traffic",  # in case a generic label exists

    # MQTT
    "MQTT_Publish": "Attack: MQTT Publish flood",

    # DoS / DDoS
    "DOS_SYN_Hping": "Attack: DoS SYN (hping3)",
    "DOS_SYN_hping": "Attack: DoS SYN (hping3)",  # alt spelling/case
    "DDOS_Slowloris": "Attack: DDoS Slowloris",

    # SSH brute force
    "Metasploit_Brute_Force_SSH": "Attack: SSH brute force (Metasploit)",
    "metasploit_Brute_force_SSH": "Attack: SSH brute force (Metasploit)",

    # ARP
    "ARP_poisioning": "Attack: ARP poisoning",

    # Nmap scans (recon)
    "NMAP_TCP_scan": "Recon: Nmap TCP scan",
    "NMAP_UDP_SCAN": "Recon: Nmap UDP scan",
    "NMAP_UDP_scan": "Recon: Nmap UDP scan",
    "NMAP_XMAS_TREE_SCAN": "Recon: Nmap Xmas tree scan",
    "NMAP_XMAS_TREE_scan": "Recon: Nmap Xmas tree scan",
    "NMAP_FIN_SCAN": "Recon: Nmap FIN scan",
    "NMAP_FIN_scan": "Recon: Nmap FIN scan",
    "NMAP_OS_DETECTION": "Recon: Nmap OS detection",
    "NMAP_OS_detection": "Recon: Nmap OS detection",
}


def map_label(raw_label: str) -> str:
    """
    Map the raw Attack_type label from the model to a nicer, human-readable label.
    If we don't have a mapping, just return the raw label.
    """
    return RAW_LABEL_TO_NICE.get(raw_label, raw_label)


# ---------------------------------------------------------------------------
#  Model + header loading
# ---------------------------------------------------------------------------

def load_model_and_header() -> None:
    """Load the sklearn pipeline and discover feature columns."""
    global pipeline, feature_columns, default_values

    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Model file not found at {MODEL_PATH.resolve()}. "
            "Train the model first with train_rf.py."
        )

    bundle = joblib.load(MODEL_PATH)
    pipeline = bundle.get("pipeline")
    if pipeline is None:
        raise RuntimeError("Loaded model bundle is missing 'pipeline' key.")

    # Prefer feature_columns from the bundle, else infer from CSV header
    if "feature_columns" in bundle:
        feature_columns = list(bundle["feature_columns"])
    else:
        if not CSV_PATH.exists():
            raise RuntimeError(
                f"CSV header not found at {CSV_PATH.resolve()} and "
                "'feature_columns' missing from model bundle."
            )
        header_df = pd.read_csv(CSV_PATH, nrows=0)
        cols = list(header_df.columns)
        if target_col in cols:
            cols.remove(target_col)
        feature_columns = cols

    # Construct default values for all features
    default_values.clear()
    for col in feature_columns:
        if col == "proto":
            default_values[col] = "tcp"
        elif col == "service":
            default_values[col] = "unknown"
        else:
            default_values[col] = 0.0

    print("[detect_server] Loaded model and feature metadata.")
    print(f"[detect_server] Feature count: {len(feature_columns)}")


def build_df_from_features(feat_dicts: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Given a list of partial feature dicts, build a DataFrame with all
    expected feature columns, filling missing ones with defaults.
    """
    rows: List[Dict[str, Any]] = []
    for f in feat_dicts:
        row = {}
        for col in feature_columns:
            if col in f and f[col] is not None:
                row[col] = f[col]
            else:
                row[col] = default_values.get(col, 0.0)
        rows.append(row)
    return pd.DataFrame(rows, columns=feature_columns)


@app.on_event("startup")
def startup_event() -> None:
    load_model_and_header()


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "model_path": str(MODEL_PATH),
        "feature_count": len(feature_columns),
        "has_label_mapping": True,
    }


@app.post("/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Model pipeline not loaded.")

    df = build_df_from_features([req.features])
    try:
        y_pred = pipeline.predict(df)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")

    raw_label = str(y_pred[0])
    nice_label = map_label(raw_label)

    proba_list: Optional[List[float]] = None
    class_labels: Optional[List[str]] = None
    if hasattr(pipeline, "predict_proba"):
        try:
            proba = pipeline.predict_proba(df)[0]
            proba_list = proba.tolist()
            class_labels = [str(c) for c in pipeline.classes_]
        except Exception:
            proba_list = None
            class_labels = None

    return {
        "prediction": nice_label,        # nice human label
        "raw_prediction": raw_label,     # raw Attack_type from dataset
        "probabilities": proba_list,
        "class_labels": class_labels,    # these are raw labels
    }


@app.post("/predict_batch")
def predict_batch(req: PredictBatchRequest) -> Dict[str, Any]:
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Model pipeline not loaded.")

    if not req.instances:
        raise HTTPException(status_code=400, detail="No instances provided.")

    df = build_df_from_features(req.instances)

    try:
        y_pred = pipeline.predict(df)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")

    raw_preds = [str(p) for p in y_pred]
    nice_preds = [map_label(p) for p in raw_preds]

    proba_array: Optional[List[List[float]]] = None
    class_labels: Optional[List[str]] = None
    if hasattr(pipeline, "predict_proba"):
        try:
            proba_array = pipeline.predict_proba(df).tolist()
            class_labels = [str(c) for c in pipeline.classes_]
        except Exception:
            proba_array = None
            class_labels = None

    return {
        "predictions": nice_preds,          # nice labels
        "raw_predictions": raw_preds,       # raw Attack_type labels
        "probabilities": proba_array,
        "class_labels": class_labels,       # raw Attack_type labels
    }


# To run directly: python3 detect_server.py
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("detect_server:app", host="0.0.0.0", port=8000, reload=True)

