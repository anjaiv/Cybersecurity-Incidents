from functools import lru_cache
from pathlib import Path
import re

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


BASE_DIR = Path(__file__).resolve().parents[1]
DATASET_PATH = BASE_DIR / "data" / "Phishing_Email.csv"
PHISHING_LABEL = "Phishing Email"
SAFE_LABEL = "Safe Email"


def clean_email_text(text: str) -> str:
    text = str(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    data = pd.read_csv(DATASET_PATH)
    required_columns = {"Email Text", "Email Type"}
    missing = required_columns.difference(data.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(sorted(missing))}")

    data = data.dropna(subset=["Email Text", "Email Type"]).copy()
    data["Email Text"] = data["Email Text"].map(clean_email_text)
    data = data[data["Email Text"].str.len() > 0]
    data = data[data["Email Type"].isin([PHISHING_LABEL, SAFE_LABEL])]
    return data


def build_pipeline() -> Pipeline:
    features = FeatureUnion(
        [
            (
                "word_tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    max_features=30000,
                    ngram_range=(1, 2),
                    min_df=2,
                ),
            ),
            (
                "char_tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    lowercase=True,
                    max_features=20000,
                    ngram_range=(3, 5),
                    min_df=2,
                ),
            ),
        ]
    )

    return Pipeline(
        [
            ("features", features),
            ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced", n_jobs=1)),
        ]
    )


@lru_cache(maxsize=1)
def get_trained_model() -> tuple[Pipeline, dict]:
    data = load_dataset()
    x = data["Email Text"]
    y = data["Email Type"]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = build_pipeline()
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    labels = [PHISHING_LABEL, SAFE_LABEL]
    matrix = confusion_matrix(y_test, y_pred, labels=labels)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, pos_label=PHISHING_LABEL)), 4),
        "recall": round(float(recall_score(y_test, y_pred, pos_label=PHISHING_LABEL)), 4),
        "f1": round(float(f1_score(y_test, y_pred, pos_label=PHISHING_LABEL)), 4),
        "train_size": int(len(x_train)),
        "test_size": int(len(x_test)),
        "labels": labels,
        "confusion_matrix": matrix.astype(int).tolist(),
    }

    return model, metrics


def predict_with_confidence(text: str) -> dict:
    cleaned = clean_email_text(text)
    model, _ = get_trained_model()
    label = str(model.predict([cleaned])[0])
    classes = list(model.named_steps["classifier"].classes_)
    probabilities = model.predict_proba([cleaned])[0]
    probability_by_label = {
        str(class_name): float(probability)
        for class_name, probability in zip(classes, probabilities)
    }

    phishing_probability = probability_by_label.get(PHISHING_LABEL, 0.0)
    safe_probability = probability_by_label.get(SAFE_LABEL, 0.0)
    predicted_confidence = probability_by_label.get(label, max(probability_by_label.values()))

    return {
        "label": label,
        "confidence": round(predicted_confidence, 4),
        "phishing_probability": round(phishing_probability, 4),
        "safe_probability": round(safe_probability, 4),
    }


def get_dataset_stats() -> dict:
    data = load_dataset()
    total = len(data)
    phishing = int((data["Email Type"] == PHISHING_LABEL).sum())
    safe = int((data["Email Type"] == SAFE_LABEL).sum())
    _, metrics = get_trained_model()

    return {
        "total_emails": total,
        "phishing_emails": phishing,
        "safe_emails": safe,
        "phishing_percentage": round((phishing / total) * 100, 2) if total else 0,
        "safe_percentage": round((safe / total) * 100, 2) if total else 0,
        "model_metrics": metrics,
    }
