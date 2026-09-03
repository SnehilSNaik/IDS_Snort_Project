"""
=============================================================
ml_model/train_autoencoder.py  —  IDS_Snort_Project
=============================================================
Trains an LSTM Autoencoder for unsupervised network anomaly
detection.

Architecture:
  Input  : Sequence of 20 packets × 15 CIC-IDS-2017 features
  Encoder: LSTM(64) → LSTM(32)  — compresses the sequence
  Decoder: RepeatVector(20) → LSTM(32) → LSTM(64) → TimeDistributed Dense
  Output : Reconstructed sequence (same shape as input)

Training Strategy (anomaly detection paradigm):
  - Trained ONLY on normal traffic from CIC-IDS-2017 Monday CSV
  - The model learns to reconstruct "normal" sequences perfectly
  - At inference time, attack sequences produce HIGH reconstruction
    error (MSE) because the model has never seen them
  - Anomaly threshold = 99th percentile of normal traffic MSE

Fallback:
  If CIC-IDS-2017 dataset not downloaded, trains on 5000 synthetic
  normal sequences generated from Gaussian distributions.

Usage:
  python ml_model/train_autoencoder.py

Output:
  ml_model/autoencoder_model.keras  (Keras SavedModel)
  ml_model/autoencoder_scaler.pkl   (StandardScaler for 15 features)
  ml_model/autoencoder_threshold.pkl (float — MSE cutoff)
=============================================================
"""

import os
import sys
import pickle
import numpy as np
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Output paths ──────────────────────────────────────────
MODEL_PATH     = os.path.join(BASE_DIR, "autoencoder_model.keras")
SCALER_PATH    = os.path.join(BASE_DIR, "autoencoder_scaler.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "autoencoder_threshold.pkl")
DATASET_DIR    = os.path.join(BASE_DIR, "dataset")

# CIC-IDS-2017 features — same 15 as the Random Forest model
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

SEQ_LEN   = 20    # packets per sequence
N_FEATURES = len(CICIDS_FEATURES)   # 15


# ─── TensorFlow import ────────────────────────────────────
def _import_tf():
    try:
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
        return tf
    except ImportError:
        print("[ERROR] TensorFlow not installed.")
        print("  Run:  pip install tensorflow")
        sys.exit(1)


# ─── Sequence builder ─────────────────────────────────────
def build_sequences(X: np.ndarray, seq_len: int = SEQ_LEN) -> np.ndarray:
    """
    Convert a 2-D feature matrix (n_samples × n_features) into
    overlapping sequences of shape (n_seq × seq_len × n_features).
    Each sequence is a sliding window shifted by 1 sample.
    """
    sequences = []
    for i in range(len(X) - seq_len + 1):
        sequences.append(X[i : i + seq_len])
    return np.array(sequences, dtype=np.float32)


# ─── Column aliases (parquet files use different names) ────
COLUMN_ALIASES = {
    "Fwd Packets Length Total":  "Total Length of Fwd Packets",
    "Avg Packet Size":           "Average Packet Size",
    "Init Fwd Win Bytes":        "Init_Win_bytes_forward",
    " Destination Port":         "Destination Port",
    "Dst Port":                  "Destination Port",
}

# ─── Load CIC-IDS-2017 normal traffic ─────────────────────
def load_cicids_normal():
    """
    Loads only BENIGN traffic from CIC-IDS-2017 Monday file.
    Supports both CSV and Parquet formats.
    Returns a scaled numpy array of shape (n, 15).
    """
    import pandas as pd
    from sklearn.preprocessing import StandardScaler

    monday_files = []
    if os.path.isdir(DATASET_DIR):
        for fname in os.listdir(DATASET_DIR):
            if "monday" in fname.lower() and (fname.endswith(".csv") or fname.endswith(".parquet")):
                monday_files.append(os.path.join(DATASET_DIR, fname))

    if not monday_files:
        # Fall back: look for any data file and take only BENIGN rows
        all_files = []
        if os.path.isdir(DATASET_DIR):
            all_files = [f for f in os.listdir(DATASET_DIR)
                         if f.endswith(".csv") or f.endswith(".parquet")]
        if not all_files:
            return None, None
        monday_files = [os.path.join(DATASET_DIR, all_files[0])]

    dfs = []
    for fpath in monday_files:
        try:
            if fpath.endswith(".parquet"):
                df = pd.read_parquet(fpath)
            else:
                df = pd.read_csv(fpath, encoding="utf-8", low_memory=False)
            df.columns = df.columns.str.strip()
            # Apply column aliases
            df.rename(columns=COLUMN_ALIASES, inplace=True)
            # Filter benign only (case-insensitive)
            label_col = next((c for c in df.columns if "label" in c.lower()), None)
            if label_col:
                df = df[df[label_col].astype(str).str.strip().str.upper() == "BENIGN"]
            dfs.append(df)
            print(f"[TRAIN] Loaded {len(df):,} benign rows from {os.path.basename(fpath)}")
        except Exception as e:
            print(f"[WARN] Could not read {fpath}: {e}")

    if not dfs:
        return None, None

    df_all = pd.concat(dfs, ignore_index=True)

    # Keep only the 15 features, drop rows with inf/nan
    available = [f for f in CICIDS_FEATURES if f in df_all.columns]
    missing = [f for f in CICIDS_FEATURES if f not in df_all.columns]
    if missing:
        print(f"[WARN] Missing features (filled with 0): {missing}")
        for feat in missing:
            df_all[feat] = 0
        available = CICIDS_FEATURES

    if len(available) < 10:
        print(f"[WARN] Only {len(available)} CIC features found. Using all available numeric columns.")
        available = df_all.select_dtypes(include=np.number).columns.tolist()[:N_FEATURES]

    df_feat = df_all[available].replace([np.inf, -np.inf], np.nan).dropna()

    # Sample up to 100K rows (sufficient for autoencoder, keeps training fast)
    if len(df_feat) > 100_000:
        df_feat = df_feat.sample(100_000, random_state=42)

    X = df_feat.values.astype(np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Pad / trim feature count to exactly N_FEATURES
    if X_scaled.shape[1] < N_FEATURES:
        pad = np.zeros((X_scaled.shape[0], N_FEATURES - X_scaled.shape[1]), dtype=np.float32)
        X_scaled = np.hstack([X_scaled, pad])
    else:
        X_scaled = X_scaled[:, :N_FEATURES]

    return X_scaled, scaler


# ─── Synthetic normal traffic fallback ───────────────────
def make_synthetic_normal(n: int = 8000):
    """
    Generates n synthetic 'normal' traffic feature vectors.
    Simulates: web browsing, video streaming, TCP ACKs.
    Returns scaled X and the fitted StandardScaler.
    """
    from sklearn.preprocessing import StandardScaler
    rng = np.random.default_rng(42)

    # Web browsing: low rate, medium size, mixed ports
    web = rng.normal(loc=[443, 1e5, 10, 5000, 800, 500, 100, 4e4, 10, 5e4, 600, 1, 2, 5, 65535],
                     scale=[200, 5e4, 5, 2000, 400, 200, 50, 2e4, 5, 2e4, 200, 0.5, 1, 2, 5000],
                     size=(n // 2, N_FEATURES))

    # TCP ACKs: tiny packets, fast rate
    acks = rng.normal(loc=[80, 5e4, 30, 1800, 60, 60, 5, 1e5, 30, 2e3, 60, 0, 0, 30, 65535],
                      scale=[10, 1e4, 10, 500, 10, 5, 2, 5e4, 10, 500, 5, 0, 0, 10, 100],
                      size=(n // 2, N_FEATURES))

    X = np.vstack([web, acks]).astype(np.float32)
    X = np.clip(X, 0, None)   # no negatives
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler


# ─── Build LSTM Autoencoder ───────────────────────────────
def build_autoencoder(tf, seq_len: int, n_features: int):
    """
    LSTM Autoencoder:
      Encoder : LSTM(64, return_sequences=True) → LSTM(32)
      Decoder : RepeatVector(seq_len) → LSTM(32, return_seq) →
                LSTM(64, return_seq) → TimeDistributed(Dense(n_features))
    """
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import (
        Input, LSTM, RepeatVector, TimeDistributed, Dense, Dropout
    )
    from tensorflow.keras.optimizers import Adam

    inp = Input(shape=(seq_len, n_features), name="input")

    # Encoder
    x = LSTM(64, return_sequences=True, name="enc_lstm1")(inp)
    x = Dropout(0.1)(x)
    encoded = LSTM(32, return_sequences=False, name="enc_lstm2")(x)

    # Bottleneck → expand back to sequence
    x = RepeatVector(seq_len, name="repeat")(encoded)

    # Decoder
    x = LSTM(32, return_sequences=True, name="dec_lstm1")(x)
    x = Dropout(0.1)(x)
    x = LSTM(64, return_sequences=True, name="dec_lstm2")(x)
    decoded = TimeDistributed(Dense(n_features), name="output")(x)

    model = Model(inp, decoded, name="lstm_autoencoder")
    model.compile(optimizer=Adam(learning_rate=1e-3), loss="mse")
    return model


# ─── Main training routine ────────────────────────────────
def train():
    tf = _import_tf()

    print("=" * 65)
    print("  LSTM Autoencoder Training — IDS_Snort_Project")
    print("=" * 65)

    # 1. Load data
    print("\n[STEP 1] Loading normal traffic data...")
    X_scaled, scaler = load_cicids_normal()

    if X_scaled is None:
        print("[INFO] CIC-IDS-2017 dataset not found. Using synthetic normal traffic.")
        X_scaled, scaler = make_synthetic_normal(8000)
        mode = "synthetic"
    else:
        mode = "CIC-IDS-2017"

    print(f"[INFO] Mode       : {mode}")
    print(f"[INFO] Data shape : {X_scaled.shape}")

    # 2. Build sequences
    print("\n[STEP 2] Building overlapping sequences (window={SEQ_LEN})...")
    X_seq = build_sequences(X_scaled, seq_len=SEQ_LEN)
    print(f"[INFO] Sequences  : {X_seq.shape}  ({X_seq.shape[0]:,} windows)")

    # Train/val split (90/10)
    split = int(len(X_seq) * 0.9)
    X_train, X_val = X_seq[:split], X_seq[split:]

    # 3. Build & train model
    print("\n[STEP 3] Building LSTM Autoencoder...")
    model = build_autoencoder(tf, SEQ_LEN, N_FEATURES)
    model.summary()

    print("\n[STEP 4] Training (up to 30 epochs, early stopping at val_loss plateau)...")
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3, verbose=1),
    ]

    history = model.fit(
        X_train, X_train,
        validation_data=(X_val, X_val),
        epochs=30,
        batch_size=256,
        callbacks=callbacks,
        verbose=1,
    )

    # 4. Compute anomaly threshold (99th percentile of normal reconstruction MSE)
    print("\n[STEP 5] Computing anomaly threshold from normal traffic MSE...")
    X_val_pred = model.predict(X_val, verbose=0)
    val_mse = np.mean(np.power(X_val - X_val_pred, 2), axis=(1, 2))
    threshold = float(np.percentile(val_mse, 99))
    print(f"[INFO] Anomaly threshold (99th pct) = {threshold:.6f}")

    # 5. Save artefacts
    print("\n[STEP 6] Saving model artefacts...")
    model.save(MODEL_PATH)
    print(f"[OK]  Model    → {MODEL_PATH}")

    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"[OK]  Scaler   → {SCALER_PATH}")

    with open(THRESHOLD_PATH, "wb") as f:
        pickle.dump(threshold, f)
    print(f"[OK]  Threshold → {THRESHOLD_PATH}")

    print("\n" + "=" * 65)
    print("  Training complete!")
    print(f"  Final val_loss : {history.history['val_loss'][-1]:.6f}")
    print(f"  MSE threshold  : {threshold:.6f}")
    print("  Run detect:    python ml_model/autoencoder.py")
    print("=" * 65)


if __name__ == "__main__":
    train()
