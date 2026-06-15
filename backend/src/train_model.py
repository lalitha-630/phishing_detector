"""
====================================
  Model Training  —  v2
====================================
Trains a Random Forest classifier and saves it as a .pkl file

v2 improvements:
  - Cross-validation instead of single train/test split
  - Confusion matrix for detailed error analysis
  - Anti-overfitting: max_depth, min_samples_leaf, class_weight
  - Calibrated probabilities (CalibratedClassifierCV)
  - Checks for train/test accuracy gap (overfitting warning)
"""

import os
import sys
import csv
import pickle
import random
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features, get_feature_names
from dataset_builder import create_dataset


def _parse_number(x: str):
    if x is None:
        return 0
    s = str(x).strip()
    if s == "":
        return 0
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return 0


def load_dataset(csv_path: str):
    """
    Supports:
      - legacy CSV: url,label
      - feature-rich CSV: url,label,<feature_1>,...,<feature_n>
    Returns: (urls, labels, X_or_None, feature_names_or_None)
    """
    urls, labels = [], []
    X = []
    feature_names = None
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames:
            extra = [c for c in reader.fieldnames if c not in ("url", "label")]
            if extra:
                feature_names = extra
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
            if feature_names:
                X.append([_parse_number(row.get(name, 0)) for name in feature_names])
    return urls, labels, (X if feature_names else None), feature_names


def prepare_features(urls: list):
    feature_names = get_feature_names()
    X = []
    for url in urls:
        features = extract_features(url)
        X.append([features[name] for name in feature_names])
    return X, feature_names


def train_model(dataset_path: str, model_output: str = "models/phishing_model.pkl"):
    print("=" * 55)
    print("         Model Training  -  v2")
    print("=" * 55)

    # ── 1. Load ────────────────────────────────────────────────
    print("\n[1/5] Loading dataset...")
    urls, labels, X_pre, feature_names_pre = load_dataset(dataset_path)
    legit_n = labels.count(0)
    phish_n = labels.count(1)
    print(f"      Loaded {len(urls)} URLs  (legit={legit_n}, phishing={phish_n})")

    # ── 2. Features ────────────────────────────────────────────
    if X_pre is not None and feature_names_pre is not None:
        print("\n[2/5] Using precomputed features from dataset...")
        X, feature_names = X_pre, feature_names_pre
        print(f"      {len(feature_names)} features loaded per URL")
    else:
        print("\n[2/5] Extracting features...")
        X, feature_names = prepare_features(urls)
        print(f"      {len(feature_names)} features extracted per URL")

    # ── 3. Split ───────────────────────────────────────────────
    print("\n[3/5] Splitting data (80/20 stratified)...")
    combined = list(zip(X, labels))
    random.seed(42)
    random.shuffle(combined)
    X_s, y_s = zip(*combined)

    split = int(len(X_s) * 0.8)
    X_train, X_test = list(X_s[:split]), list(X_s[split:])
    y_train, y_test = list(y_s[:split]), list(y_s[split:])
    print(f"      Train: {len(X_train)} | Test: {len(X_test)}")

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (accuracy_score, classification_report,
                                     confusion_matrix)
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.model_selection import cross_val_score
        import numpy as np

        # ── 4. Train ───────────────────────────────────────────
        print("\n[4/5] Training Random Forest (anti-overfitting settings)...")

        base_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=8,            # Limit depth → less memorization
            min_samples_leaf=3,     # Each leaf needs ≥3 samples
            min_samples_split=6,    # Each split needs ≥6 samples
            max_features="sqrt",    # Use sqrt(features) per split
            class_weight="balanced",# Handle class imbalance fairly
            random_state=42,
        )

        # Cross-validation on training set (5-fold)
        cv_scores = cross_val_score(base_model, X_train, y_train, cv=5,
                                    scoring="accuracy")
        print(f"\n  5-fold CV on train set:")
        print(f"    Scores : {[f'{s:.3f}' for s in cv_scores]}")
        print(f"    Mean   : {cv_scores.mean():.3f}  +/-{cv_scores.std():.3f}")

        # Calibrated model for realistic probabilities
        calibrated = CalibratedClassifierCV(base_model, cv=5, method="isotonic")
        calibrated.fit(X_train, y_train)

        # ── 5. Evaluate ────────────────────────────────────────
        print("\n[5/5] Evaluating on test set...")

        y_pred_train = calibrated.predict(X_train)
        y_pred_test  = calibrated.predict(X_test)
        train_acc    = accuracy_score(y_train, y_pred_train)
        test_acc     = accuracy_score(y_test,  y_pred_test)
        gap          = train_acc - test_acc

        report = classification_report(
            y_test, y_pred_test,
            target_names=["Legitimate", "Phishing"],
            output_dict=True,
        )
        cm = confusion_matrix(y_test, y_pred_test)

        print(f"\n  +-----------------------------------------+")
        print(f"  |  Train accuracy : {train_acc*100:5.1f}%                |")
        print(f"  |  Test  accuracy : {test_acc*100:5.1f}%                |")
        print(f"  |  Overfit gap    : {gap*100:5.1f}%  ", end="")
        if gap < 0.05:
            print("OK (healthy)         |")
        elif gap < 0.10:
            print("! (mild overfit)     |")
        else:
            print("X (overfitting!)     |")
        print(f"  +-----------------------------------------+")

        print(f"\n  Class breakdown (test set):")
        for cls in ["Legitimate", "Phishing"]:
            r = report[cls]
            print(f"    {cls:<12} Precision={r['precision']:.2f}  "
                  f"Recall={r['recall']:.2f}  F1={r['f1-score']:.2f}")

        print(f"\n  Confusion matrix:")
        print(f"                 Pred Legit  Pred Phish")
        print(f"    True Legit     {cm[0][0]:^10d}{cm[0][1]:^10d}")
        print(f"    True Phish     {cm[1][0]:^10d}{cm[1][1]:^10d}")
        if cm[1][0] > 0:
            print(f"\n  ! False negatives (missed phishing): {cm[1][0]}")
        if cm[0][1] > 0:
            print(f"  ! False positives (legit flagged): {cm[0][1]}")

        # Feature importance
        base_model.fit(X_train, y_train)   # fit bare model for importances
        importances = sorted(
            zip(feature_names, base_model.feature_importances_),
            key=lambda x: x[1], reverse=True,
        )
        print(f"\n  Top 8 Feature Importances:")
        for name, imp in importances[:8]:
            bar = "#" * int(imp * 80)
            print(f"    {name:<30} {bar} {imp:.3f}")

    except ImportError:
        print("  scikit-learn not found. Run: pip install scikit-learn")
        return None

    # ── Save ───────────────────────────────────────────────────
    payload = {
        "model": calibrated,
        "feature_names": feature_names,
        "test_accuracy": test_acc,
        "train_accuracy": train_acc,
        "cv_mean": float(cv_scores.mean()),
        "trained_on": len(X_train),
        "accuracy": test_acc,
    }

    out_dir = os.path.dirname(model_output) or "."
    base = os.path.basename(model_output)
    stem, ext = os.path.splitext(base)
    if not ext:
        ext = ".pkl"

    save_candidates = [
        model_output,
        os.path.join(out_dir, f"{stem}_new{ext}"),
        os.path.join(out_dir, f"{stem}_{os.getpid()}_{int(time.time())}{ext}"),
    ]
    seen_paths = set()
    paths = []
    for p in save_candidates:
        if p not in seen_paths:
            seen_paths.add(p)
            paths.append(p)

    saved_path = None
    last_save_err = None
    for path in paths:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump(payload, f)
            saved_path = path
            break
        except (PermissionError, OSError) as e:
            last_save_err = e
            print(f"  [train] Could not write model {path!r}: {e}")
            continue

    if saved_path is None:
        raise last_save_err

    if saved_path != model_output:
        print(f"  [train] Model saved to fallback path: {saved_path!r}")

    print(f"\n  Model saved -> {saved_path}")
    print("\n" + "=" * 55)
    print("  Training complete!")
    print("=" * 55)
    return saved_path


def predict_url(url: str, model_path: str = "models/phishing_model.pkl"):
    with open(model_path, "rb") as f:
        data = pickle.load(f)

    features = extract_features(url)
    X = [[features[n] for n in data["feature_names"]]]
    pred = data["model"].predict(X)[0]
    prob = data["model"].predict_proba(X)[0]

    confidence = max(prob)
    if pred == 1:
        risk = "HIGH" if confidence > 0.80 else "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url":         url,
        "status":      "Phishing" if pred == 1 else "Legitimate",
        "confidence":  f"{confidence * 100:.1f}%",
        "risk_level":  risk,
        "is_phishing": bool(pred == 1),
    }


if __name__ == "__main__":
    dataset_path = create_dataset("data/dataset.csv")
    model_path   = train_model(dataset_path, "models/phishing_model.pkl")

    if model_path:
        print("\nQuick Test (mix of easy + tricky):")
        print("-" * 65)
        test_urls = [
            # Easy legit
            "https://www.google.com",
            "https://www.amazon.com/dp/B08N5KWB9H",
            # Tricky legit (has /login, /account, hyphens)
            "https://accounts.google.com/signin",
            "https://www.facebook.com/login",
            "https://www.t-mobile.com",
            "https://myaccount.google.com/security",
            "https://www.paypal.com/myaccount/summary",
            # Easy phishing
            "http://paypal-login-verify.phish.com",
            "http://192.168.1.1/login.php",
            # Tricky phishing (HTTPS, lookalike)
            "https://paypa1.com/login/secure/verify",
            "https://arnazon-orders.com/account/verify",
            "https://paypal.phish-secure.com/wallet/signin",
            "https://secure-chase-bank.credential-steal.com/login",
        ]
        for url in test_urls:
            r = predict_url(url, model_path)
            icon = "[PHISH]" if r["is_phishing"] else "[SAFE] "
            print(f"  {icon}  {r['confidence']:>6}  {url}")
