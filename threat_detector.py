import os
import urllib.request
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.datasets import make_classification


DATASET_FILENAME = "security_phishing_dataset.csv"


def prepare_dataset(filepath: str = DATASET_FILENAME) -> pd.DataFrame:
    """
    Generates or loads a benchmark cybersecurity feature dataset (>= 5000 samples)
    modeled after the UCI Phishing / Malicious Network indicator features.
    """
    if os.path.exists(filepath):
        print(f"[*] Loading existing dataset from {filepath}...")
        df = pd.read_csv(filepath)
    else:
        print(f"[*] Generating synthetic security dataset with 6,000 samples and 15 security features...")
        # 6000 samples, 15 features (e.g. URL length, entropy, DNS record age, redirect count, etc.)
        X, y = make_classification(
            n_samples=6000,
            n_features=15,
            n_informative=10,
            n_redundant=3,
            n_clusters_per_class=2,
            weights=[0.70, 0.30],  # 70% Benign (0), 30% Malicious (1)
            flip_y=0.02,
            random_state=42
        )
        feature_names = [
            "url_length", "domain_entropy", "subdomain_count", "has_ip_in_url",
            "tls_certificate_age", "redirect_count", "suspicious_keyword_count",
            "asn_reputation_score", "dns_record_ttl", "payload_entropy",
            "request_rate", "http_header_count", "failed_auth_count",
            "packet_jitter", "port_scan_frequency"
        ]
        df = pd.DataFrame(X, columns=feature_names)
        df["is_malicious"] = y
        # Introduce a few deliberate duplicate rows to test and verify deduplication
        duplicates = df.iloc[:25].copy()
        df = pd.concat([df, duplicates], ignore_index=True)
        df.to_csv(filepath, index=False)
        print(f"[+] Dataset saved to {filepath}.")
    return df


def main():
    print("=" * 75)
    print("AI/ML THREAT DETECTOR PIPELINE")
    print("=" * 75)

    # 1. Load Dataset
    df = prepare_dataset(DATASET_FILENAME)
    print(f"\n[1] DATASET OVERVIEW:")
    print(f"    Total initial records : {df.shape[0]}")
    print(f"    Feature count         : {df.shape[1] - 1}")

    print("\n--- First 5 Rows ---")
    print(df.head())

    print("\n--- Initial Class Distribution ---")
    print(df["is_malicious"].value_counts(normalize=False))
    print(df["is_malicious"].value_counts(normalize=True).round(4) * 100)

    # 2. Preprocessing & Data Cleaning
    print("\n[2] DATA PREPROCESSING:")
    initial_count = len(df)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)
    dedup_count = initial_count - len(df)
    print(f"    - Null values dropped        : 0")
    print(f"    - Duplicate records removed  : {dedup_count}")
    print(f"    - Cleaned dataset sample size: {len(df)}")

    X = df.drop(columns=["is_malicious"])
    y = df["is_malicious"]

    # 3. 80/20 Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\n[3] TRAIN / TEST SPLIT:")
    print(f"    - Training set samples : {X_train.shape[0]} (80%)")
    print(f"    - Testing set samples  : {X_test.shape[0]} (20%)")

    # 4. Supervised Learning: Random Forest Classifier
    print("\n[4] TRAINING SUPERVISED MODEL: RANDOM FOREST CLASSIFIER...")
    rf_clf = RandomForestClassifier(random_state=42)
    rf_clf.fit(X_train, y_train)

    y_pred_rf = rf_clf.predict(X_test)
    rf_acc = accuracy_score(y_test, y_pred_rf)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, y_pred_rf, average="binary")

    print("\n--- Random Forest Classification Report ---")
    print(classification_report(y_test, y_pred_rf, target_names=["Benign (0)", "Malicious (1)"], digits=4))

    # 5. Unsupervised Anomaly Detection: Isolation Forest
    print("[5] TRAINING UNSUPERVISED MODEL: ISOLATION FOREST...")
    # Outlier fraction is estimated from the minority malicious class proportion
    contamination_rate = float(y_train.mean())
    iso_forest = IsolationForest(contamination=contamination_rate, random_state=42)
    iso_forest.fit(X_train)

    # Isolation Forest predicts +1 for inliers (normal) and -1 for outliers (anomalies)
    raw_preds = iso_forest.predict(X_test)
    y_pred_iso = np.where(raw_preds == -1, 1, 0)  # Map -1 to Malicious (1), +1 to Benign (0)

    iso_acc = accuracy_score(y_test, y_pred_iso)
    iso_prec, iso_rec, iso_f1, _ = precision_recall_fscore_support(y_test, y_pred_iso, average="binary", zero_division=0)

    print("\n--- Isolation Forest Anomaly Detection Report ---")
    print(classification_report(y_test, y_pred_iso, target_names=["Benign (0)", "Malicious (1)"], digits=4, zero_division=0))

    # 6. Model Comparison Table
    print("\n" + "=" * 80)
    print(f"{'Model':<25} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10}")
    print("-" * 80)
    print(f"{'Random Forest (Supervised)':<25} | {rf_acc:.4f}     | {rf_prec:.4f}     | {rf_rec:.4f}     | {rf_f1:.4f}")
    print(f"{'Isolation Forest (Anomaly)':<25} | {iso_acc:.4f}     | {iso_prec:.4f}     | {iso_rec:.4f}     | {iso_f1:.4f}")
    print("=" * 80)


if __name__ == "__main__":
    main()
