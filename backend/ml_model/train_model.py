"""
=============================================================
ml_model/train_model.py
=============================================================
Trains a Random Forest classifier to detect anomalous
network traffic.

Two training modes:
  1. REAL DATA  — Uses the CIC-IDS-2017 dataset (if downloaded
     to ml_model/dataset/). 78 flow-level features, 15 selected
     for live detection compatibility.
  2. SYNTHETIC  — Falls back to synthetic data modeled on
     CIC-IDS-2017 profiles (3 basic features).

The mode is auto-detected based on whether dataset/ exists.
=============================================================
"""

import os
import glob
import pickle
import sys
# pyarrow is vendored in backend/vendor on Windows when the user Python site
# directory is not writable. This keeps CIC-IDS Parquet training reproducible.
VENDOR_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")
if os.path.isdir(VENDOR_DIR) and VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)
import pandas as pd
import numpy as np
import json
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# --------------------------------------------------------
# Paths
# --------------------------------------------------------
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR    = os.path.join(BASE_DIR, "dataset")
# Training data is supplied from the curated dataset directory; live capture is
# handled by Snort/Npcap and is intentionally not written to standalone CSV files.
DATA_FILE      = os.path.join(BASE_DIR, "dataset", "training_packets.csv")
MODEL_FILE     = os.path.join(BASE_DIR, "model.pkl")
SCALER_FILE    = os.path.join(BASE_DIR, "scaler.pkl")
FEATURE_CFG    = os.path.join(BASE_DIR, "feature_config.pkl")
METRICS_FILE   = os.path.join(BASE_DIR, "metrics.json")

# --------------------------------------------------------
# CIC-IDS-2017 Feature Selection
# --------------------------------------------------------
# These 15 features can be approximated from live packets
# using a sliding window in detect.py. They bridge the gap
# between flow-level training data and packet-level detection.
#
# CANONICAL names used by detect.py (must match this list):
CICIDS_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Mean",
    "Average Packet Size",
    "SYN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
]

# Column name mapping: parquet/alternate name -> canonical name
# The Kaggle "no-metadata" parquet files use different column names.
COLUMN_ALIASES = {
    "Fwd Packets Length Total":  "Total Length of Fwd Packets",
    "Avg Packet Size":           "Average Packet Size",
    "Init Fwd Win Bytes":        "Init_Win_bytes_forward",
    "Init_Win_bytes_forward":    "Init_Win_bytes_forward",
    " Destination Port":         "Destination Port",
    "Dst Port":                  "Destination Port",
}


# --------------------------------------------------------
# Load CIC-IDS-2017 real dataset (CSV or Parquet)
# --------------------------------------------------------
def load_cicids2017():
    """
    Loads the real CIC-IDS-2017 dataset from ml_model/dataset/.
    Supports both CSV and Parquet file formats.
    Handles:
      - Merging multiple day-wise files
      - Stripping whitespace from column names
      - Mapping alternate column names to canonical names
      - Dropping NaN / Inf values
      - Binary label encoding (BENIGN=0, all attacks=1)
      - Balanced sampling to handle class imbalance
    Returns a cleaned DataFrame with selected features + label.
    """
    csv_files     = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    parquet_files = glob.glob(os.path.join(DATASET_DIR, "*.parquet"))
    data_files    = csv_files + parquet_files

    if not data_files:
        return None

    fmt = "Parquet" if parquet_files else "CSV"
    print(f"[INFO] Found {len(data_files)} CIC-IDS-2017 {fmt} files:")
    for f in data_files:
        size_mb = os.path.getsize(f) / 1024 / 1024
        print(f"  → {os.path.basename(f)} ({size_mb:.1f} MB)")

    # Load and merge all files
    dfs = []
    for f in data_files:
        try:
            if f.endswith(".parquet"):
                chunk = pd.read_parquet(f)
            else:
                chunk = pd.read_csv(f, encoding="utf-8", low_memory=False)
            # Strip whitespace from column names
            chunk.columns = chunk.columns.str.strip()
            # Apply column aliases
            chunk.rename(columns=COLUMN_ALIASES, inplace=True)
            dfs.append(chunk)
            print(f"  [OK] Loaded {os.path.basename(f)}: {len(chunk)} rows")
        except Exception as e:
            print(f"  [FAIL] Error loading {os.path.basename(f)}: {e}")
            continue

    if not dfs:
        print("[ERROR] No CSV files could be loaded!")
        return None

    df = pd.concat(dfs, ignore_index=True)
    print(f"\n[INFO] Combined dataset: {len(df)} rows, {len(df.columns)} columns")

    # ── Verify required columns exist ──────────────────────
    # Find the label column (may be 'Label' or ' Label')
    label_col = None
    for col in df.columns:
        if col.strip().lower() == "label":
            label_col = col
            break

    if label_col is None:
        print("[ERROR] No 'Label' column found in dataset!")
        print(f"  Available columns: {list(df.columns[:10])}...")
        return None

    # Check which selected features are available
    available_features = []
    missing_features = []
    for feat in CICIDS_FEATURES:
        if feat in df.columns:
            available_features.append(feat)
        else:
            # Try case-insensitive match
            matched = [c for c in df.columns if c.strip().lower() == feat.lower()]
            if matched:
                # Rename to our expected name
                df.rename(columns={matched[0]: feat}, inplace=True)
                available_features.append(feat)
            else:
                missing_features.append(feat)

    if missing_features:
        print(f"[WARN] Missing features (will be filled with 0): {missing_features}")
        for feat in missing_features:
            df[feat] = 0
        available_features = CICIDS_FEATURES  # Use all after filling

    print(f"[INFO] Using {len(available_features)} features for training")

    # ── Binary label encoding ─────────────────────────────
    # Case-insensitive: parquet files use 'Benign', CSVs use 'BENIGN'
    df["label"] = (df[label_col].astype(str).str.strip().str.upper() != "BENIGN").astype(int)

    # Show attack type distribution
    attack_types = df[label_col].str.strip().value_counts()
    print(f"\n[INFO] Traffic distribution:")
    for atype, count in attack_types.items():
        pct = count / len(df) * 100
        marker = "+" if atype == "BENIGN" else "-"
        print(f"  {marker} {atype}: {count:,} ({pct:.1f}%)")

    # ── Select features + clean ───────────────────────────
    feature_cols = CICIDS_FEATURES
    df_selected = df[feature_cols + ["label"]].copy()

    # Replace inf values with NaN, then drop NaN rows
    df_selected.replace([np.inf, -np.inf], np.nan, inplace=True)
    rows_before = len(df_selected)
    df_selected.dropna(inplace=True)
    rows_after = len(df_selected)
    if rows_before != rows_after:
        print(f"[INFO] Dropped {rows_before - rows_after} rows with NaN/Inf values")

    # Convert all feature columns to numeric
    for col in feature_cols:
        df_selected[col] = pd.to_numeric(df_selected[col], errors="coerce")
    df_selected.dropna(inplace=True)

    # ── Balance the dataset ───────────────────────────────
    # CIC-IDS-2017 is ~80% benign. Downsample benign to 1:1 ratio
    benign = df_selected[df_selected["label"] == 0]
    attack = df_selected[df_selected["label"] == 1]

    print(f"\n[INFO] Before balancing: Benign={len(benign):,}, Attack={len(attack):,}")

    if len(benign) > len(attack) * 2:
        # Downsample benign to 1.5x attack count (slight over-representation is OK)
        n_benign = int(len(attack) * 1.5)
        benign_sampled = benign.sample(n=min(n_benign, len(benign)), random_state=42)
        df_balanced = pd.concat([benign_sampled, attack], ignore_index=True)
    else:
        df_balanced = df_selected

    df_balanced = df_balanced.sample(frac=1, random_state=42)  # Shuffle
    print(f"[INFO] After balancing: {len(df_balanced):,} samples "
          f"(Benign={len(df_balanced[df_balanced['label']==0]):,}, "
          f"Attack={len(df_balanced[df_balanced['label']==1]):,})")

    return df_balanced


# --------------------------------------------------------
# Generate synthetic training data (Fallback)
# --------------------------------------------------------
def generate_synthetic_data(n_samples=3000):
    np.random.seed(42)

    # ── NORMAL TRAFFIC ──────────────────────────────────────
    # 1. Normal Web Browsing (Low rate, mixed size)
    n1 = int(n_samples * 0.25)
    normal_web = pd.DataFrame({
        "packet_size": np.random.uniform(60, 1500, n1),
        "protocol_enc": np.random.choice([0, 1], size=n1, p=[0.8, 0.2]),
        "packet_rate": np.random.uniform(0.1, 30, size=n1),
        "label": 0
    })

    # 2. Normal Video Streaming / Downloads (Moderate-High rate, large size)
    n2 = int(n_samples * 0.15)
    normal_stream = pd.DataFrame({
        "packet_size": np.random.uniform(1200, 1500, n2),
        "protocol_enc": np.random.choice([0, 1], size=n2, p=[0.7, 0.3]),
        "packet_rate": np.random.uniform(30, 120, size=n2),
        "label": 0
    })

    # 3. Normal TCP ACKs / keepalives (Very small packets, low-moderate rate)
    n3 = int(n_samples * 0.10)
    normal_acks = pd.DataFrame({
        "packet_size": np.random.uniform(54, 66, n3),
        "protocol_enc": np.zeros(n3),  # TCP = 0
        "packet_rate": np.random.uniform(1, 30, size=n3),
        "label": 0
    })

    # ── ATTACK TRAFFIC ──────────────────────────────────────
    # 4. Realistic ICMP Ping Flood (5–200 pkt/s, small size ~64-120 bytes)
    n4 = int(n_samples * 0.15)
    attack_icmp_realistic = pd.DataFrame({
        "packet_size": np.random.uniform(64, 120, n4),
        "protocol_enc": np.ones(n4) * 2,  # ICMP = 2
        "packet_rate": np.random.uniform(5, 200, size=n4),
        "label": 1
    })

    # 5. High-speed ICMP Flood (extreme rate)
    n5 = int(n_samples * 0.10)
    attack_icmp_high = pd.DataFrame({
        "packet_size": np.random.uniform(64, 128, n5),
        "protocol_enc": np.ones(n5) * 2,  # ICMP = 2
        "packet_rate": np.random.uniform(200, 5000, size=n5),
        "label": 1
    })

    # 6. Realistic TCP SYN / Port Scan (10–300 pkt/s, tiny size < 60)
    n6 = int(n_samples * 0.15)
    attack_tcp_realistic = pd.DataFrame({
        "packet_size": np.random.uniform(40, 60, n6),
        "protocol_enc": np.zeros(n6),  # TCP = 0
        "packet_rate": np.random.uniform(10, 300, size=n6),
        "label": 1
    })

    # 7. High-speed TCP SYN Flood
    n7 = int(n_samples * 0.10)
    attack_tcp_high = pd.DataFrame({
        "packet_size": np.random.uniform(40, 60, n7),
        "protocol_enc": np.zeros(n7),  # TCP = 0
        "packet_rate": np.random.uniform(300, 5000, size=n7),
        "label": 1
    })

    # Combine all
    df = pd.concat([
        normal_web, normal_stream, normal_acks,
        attack_icmp_realistic, attack_icmp_high,
        attack_tcp_realistic, attack_tcp_high
    ], ignore_index=True)
    df = df.sample(frac=1, random_state=42)  # shuffle

    print(f"[INFO] Synthetic dataset (CIC-IDS-2017 Modeled): {len(df)} samples")
    print(f"[INFO] Normal: {(df.label==0).sum()} | Attack: {(df.label==1).sum()}")
    return df


# --------------------------------------------------------
# Load real captured data
# --------------------------------------------------------
def load_real_data(filepath):

    df = pd.read_csv(filepath)
    print(f"[INFO] Loaded {len(df)} packets")

    proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "Other": 3}
    df["protocol_enc"] = df["protocol"].map(proto_map).fillna(3).astype(int)

    df["timestamp"] = pd.to_datetime(df["timestamp"], format='mixed', errors='coerce')
    df = df.dropna(subset=["timestamp"]) # Drop any invalid timestamps that couldn't be parsed
    df = df.sort_values("timestamp")

    df["packet_rate"] = df["timestamp"].diff().dt.total_seconds().fillna(0.1)
    df["packet_rate"] = (1 / df["packet_rate"].replace(0, 0.001)).clip(upper=1000)

    # Note: Hypersensitive labels
    df["label"] = ((df["packet_size"] > 500) | (df["packet_rate"] > 2.5)).astype(int)

    return df[["packet_size", "protocol_enc", "packet_rate", "label"]]


# --------------------------------------------------------
# Train model
# --------------------------------------------------------
def train():

    print("=" * 65)
    print("  IDS ML Model Training")
    print("=" * 65)

    # ── Try loading REAL CIC-IDS-2017 dataset first ───────
    cicids_data = None
    dataset_csvs    = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    dataset_parquet = glob.glob(os.path.join(DATASET_DIR, "*.parquet"))
    if dataset_csvs or dataset_parquet:
        print("\n[MODE] REAL DATA — CIC-IDS-2017 dataset detected!")
        print(f"[INFO] Dataset directory: {DATASET_DIR}")
        cicids_data = load_cicids2017()

    if cicids_data is not None and len(cicids_data) > 100:
        # ── REAL DATA MODE ────────────────────────────────
        feature_mode = "cicids2017"
        feature_names = CICIDS_FEATURES

        X = cicids_data[feature_names].values
        y = cicids_data["label"].values

        print(f"\n[INFO] Training with REAL CIC-IDS-2017 data")
        print(f"[INFO] Features: {len(feature_names)}")
        print(f"[INFO] Samples: {len(y):,} | Benign: {(y==0).sum():,} | Attack: {(y==1).sum():,}")

        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test  = scaler.transform(X_test)

        # Model — Random Forest for better accuracy on real data
        print("\n[INFO] Training Random Forest Classifier...")
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,       # Use all CPU cores
            class_weight="balanced",
        )
        model.fit(X_train, y_train)

        # Feature importance
        importances = model.feature_importances_
        feat_imp = sorted(zip(feature_names, importances), key=lambda x: -x[1])
        print("\n[INFO] Feature Importances (Top 10):")
        for fname, imp in feat_imp[:10]:
            bar = "█" * int(imp * 50)
            print(f"  {fname:35s} {imp:.4f} {bar}")

    else:
        # ── SYNTHETIC DATA MODE (Fallback) ────────────────
        feature_mode = "synthetic"
        feature_names = ["packet_size", "protocol_enc", "packet_rate"]

        print("\n[MODE] SYNTHETIC DATA — CIC-IDS-2017 dataset not found")
        print(f"[INFO] To use real data, run: python ml_model/download_dataset.py")
        print(f"[INFO] Generating synthetic training data...\n")

        df = generate_synthetic_data()
        X = df[feature_names].values
        y = df["label"].values

        print(f"\n[INFO] Samples: {len(y)} | Anomalies: {y.sum()}")

        # Split
        classes, counts = np.unique(y, return_counts=True)
        if len(classes) > 1 and np.min(counts) >= 2:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
        else:
            print("[WARN] Not enough samples per class for stratification. Stratification disabled.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

        # Scale
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test  = scaler.transform(X_test)

        # Model — Decision Tree for synthetic data (backward compatible)
        model = DecisionTreeClassifier(max_depth=5, random_state=42)
        model.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()

    print(f"\n{'='*65}")
    print(f"  EVALUATION RESULTS  ({feature_mode.upper()} mode)")
    print(f"{'='*65}")
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"\nClassification Report:\n")
    n_classes = len(np.unique(y_test))
    if n_classes == 2:
        print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    else:
        print(classification_report(y_test, y_pred))

    # ── Save model + scaler + feature config ──────────────
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    with open(SCALER_FILE, "wb") as f:
        pickle.dump(scaler, f)

    # Save feature config — tells detect.py which features to extract
    feature_config = {
        "mode": feature_mode,             # "cicids2017" or "synthetic"
        "features": feature_names,        # list of feature names
        "n_features": len(feature_names),  # number of features
    }
    with open(FEATURE_CFG, "wb") as f:
        pickle.dump(feature_config, f)

    # Persist held-out evaluation results for the dashboard. These are training
    # metrics, never inferred from live alerts.
    metrics = {
        "status": "ok", "model": type(model).__name__, "mode": feature_mode,
        "dataset_samples": int(len(y)), "test_samples": int(len(y_test)),
        "accuracy": round(float(accuracy_score(y_test, y_pred)) * 100, 2),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)) * 100, 2),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)) * 100, 2),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)) * 100, 2),
        "confusion_matrix": {"tn": cm[0][0], "fp": cm[0][1], "fn": cm[1][0], "tp": cm[1][1]},
        "features": feature_names,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n{'='*65}")
    print(f"  FILES SAVED")
    print(f"{'='*65}")
    print(f"  Model:          {MODEL_FILE}")
    print(f"  Scaler:         {SCALER_FILE}")
    print(f"  Feature Config: {FEATURE_CFG}")
    print(f"  Mode:           {feature_mode.upper()}")
    print(f"  Features:       {len(feature_names)}")
    print(f"{'='*65}")
    print(f"\n  Model saved successfully!")


# --------------------------------------------------------
if __name__ == "__main__":
    train()
