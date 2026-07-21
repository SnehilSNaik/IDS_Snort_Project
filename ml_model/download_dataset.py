"""
=============================================================
ml_model/download_dataset.py
=============================================================
Downloads the real CIC-IDS-2017 dataset (MachineLearningCSV).

Since the CIC server now requires browser-based access, this
script will:
  1. Try to install and use the Kaggle API (if credentials exist)
  2. Open the browser to Kaggle download page as fallback
  3. Print clear manual download instructions

After downloading, place CSV files in: ml_model/dataset/
Then run: python ml_model/train_model.py

Usage:
    python ml_model/download_dataset.py
=============================================================
"""

import os
import sys
import glob
import webbrowser
import subprocess

# -- Paths ---
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

# Expected CSV file names
EXPECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

KAGGLE_DATASET = "cicdataset/cicids2017"
KAGGLE_URL     = "https://www.kaggle.com/datasets/cicdataset/cicids2017"


def check_existing_csvs():
    """Check if CSV files already exist in the dataset directory."""
    if not os.path.exists(DATASET_DIR):
        return []
    existing = []
    for f in os.listdir(DATASET_DIR):
        if f.endswith('.csv'):
            fpath = os.path.join(DATASET_DIR, f)
            size = os.path.getsize(fpath)
            if size > 1024 * 1024:  # At least 1MB to be a real CSV
                existing.append((f, size))
    return existing


def try_kaggle_download():
    """Try downloading via Kaggle API."""
    try:
        # Check if kaggle is installed
        import kaggle
        print("  [OK] Kaggle API found!")
        print(f"  Downloading dataset: {KAGGLE_DATASET}")
        print(f"  Destination: {DATASET_DIR}")
        print()

        kaggle.api.authenticate()
        kaggle.api.dataset_download_files(
            KAGGLE_DATASET,
            path=DATASET_DIR,
            unzip=True,
            quiet=False,
        )
        return True
    except ImportError:
        print("  Kaggle package not installed.")
        print("  Attempting to install kaggle...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "kaggle", "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            import kaggle
            print("  [OK] Kaggle installed!")
            kaggle.api.authenticate()
            kaggle.api.dataset_download_files(
                KAGGLE_DATASET,
                path=DATASET_DIR,
                unzip=True,
                quiet=False,
            )
            return True
        except Exception as e:
            print(f"  Could not use Kaggle API: {e}")
            return False
    except Exception as e:
        print(f"  Kaggle API error: {e}")
        return False


def print_instructions():
    """Print manual download instructions and open browser."""
    print()
    print("=" * 65)
    print("  HOW TO DOWNLOAD THE CIC-IDS-2017 DATASET")
    print("=" * 65)
    print()
    print("  The CIC-IDS-2017 dataset must be downloaded manually.")
    print("  It contains ~2.8 million labeled network flows for")
    print("  training the intrusion detection ML model.")
    print()
    print("  STEP 1: Download from Kaggle")
    print("  -------")
    print(f"    URL: {KAGGLE_URL}")
    print("    - Create a free Kaggle account (if you don't have one)")
    print("    - Click the 'Download' button on the dataset page")
    print("    - The download is ~350 MB (ZIP compressed)")
    print()
    print("  STEP 2: Extract the CSV files")
    print("  -------")
    print(f"    Extract ALL CSV files to:")
    print(f"      {DATASET_DIR}")
    print()
    print("  STEP 3: Train the model")
    print("  -------")
    print("    Run: python ml_model/train_model.py")
    print()
    print("  EXPECTED FILES (any subset works):")
    for f in EXPECTED_FILES:
        print(f"    - {f}")
    print()
    print("=" * 65)


def main():
    print()
    print("=" * 65)
    print("  CIC-IDS-2017 Dataset Downloader")
    print("  University of New Brunswick / Canadian Institute for Cybersecurity")
    print("=" * 65)
    print()

    os.makedirs(DATASET_DIR, exist_ok=True)

    # Check for existing CSV files
    existing = check_existing_csvs()
    if existing:
        print(f"  Dataset already present ({len(existing)} CSV files):")
        total = 0
        for fname, size in existing:
            print(f"    [OK] {fname} ({size/1024/1024:.1f} MB)")
            total += size
        print(f"\n  Total: {total/1024/1024:.1f} MB")
        print(f"\n  Ready to train! Run: python ml_model/train_model.py")
        return

    # Try Kaggle API first
    print("  Method 1: Attempting Kaggle API download...")
    print()
    if try_kaggle_download():
        csvs = check_existing_csvs()
        if csvs:
            total = sum(s for _, s in csvs)
            print()
            print("=" * 65)
            print(f"  SUCCESS! {len(csvs)} CSV files ready ({total/1024/1024:.1f} MB)")
            print(f"  Next step: python ml_model/train_model.py")
            print("=" * 65)
            return

    # Fallback: open browser and show instructions
    print()
    print("  Method 2: Opening Kaggle in your browser...")
    try:
        webbrowser.open(KAGGLE_URL)
        print(f"  [OK] Opened: {KAGGLE_URL}")
    except Exception:
        print(f"  Could not open browser automatically.")
        print(f"  Please visit: {KAGGLE_URL}")

    print_instructions()


if __name__ == "__main__":
    main()
