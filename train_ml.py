import os
import sys
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

MINILM_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_ENCODER_CACHE = {}


def _load_encoder(model_name=MINILM_MODEL, model_path=None):
    source = model_path if model_path and os.path.isdir(model_path) else model_name
    if source not in _ENCODER_CACHE:
        from sentence_transformers import SentenceTransformer
        _ENCODER_CACHE[source] = SentenceTransformer(source)
    return _ENCODER_CACHE[source]


class MiniLMTextFeatures(BaseEstimator, TransformerMixin):
    """all-MiniLM-L6-v2 embeddings + word TF-IDF features."""

    def __init__(self, model_name=MINILM_MODEL, model_path=None, batch_size=64,
                 word_ngram_range=(1, 2), min_df=2):
        self.model_name = model_name
        self.model_path = model_path
        self.batch_size = batch_size
        self.word_ngram_range = word_ngram_range
        self.min_df = min_df

    def fit(self, X, y=None):
        from sklearn.feature_extraction.text import TfidfVectorizer
        texts = [str(x) for x in X]
        self.word_vectorizer_ = TfidfVectorizer(
            stop_words="english",
            ngram_range=self.word_ngram_range,
            min_df=self.min_df,
            sublinear_tf=True,
        )
        word_matrix = self.word_vectorizer_.fit_transform(texts)
        self.feature_names_ = self._rank_terms(word_matrix, y)
        return self

    def transform(self, X):
        from scipy.sparse import csr_matrix, hstack
        if isinstance(X, str):
            X = [X]
        texts = [str(x) for x in X]
        embeddings = _load_encoder(self.model_name, self.model_path).encode(
            texts,
            batch_size=self.batch_size,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        return hstack(
            [csr_matrix(embeddings), self.word_vectorizer_.transform(texts)],
            format="csr",
        )

    def get_feature_names_out(self, input_features=None):
        return np.asarray(getattr(self, "feature_names_", []), dtype=object)

    def _rank_terms(self, word_matrix, y):
        names = self.word_vectorizer_.get_feature_names_out()
        if y is not None:
            y = np.asarray(y)
        if y is None or len(np.unique(y)) < 2:
            return [str(t) for t in names if len(str(t)) >= 3]
        from sklearn.naive_bayes import MultinomialNB
        nb = MultinomialNB().fit(word_matrix, y)
        scores = nb.feature_log_prob_[1] - nb.feature_log_prob_[0]
        ranked = []
        for idx in np.argsort(scores)[::-1]:
            if scores[idx] <= 0:
                break
            term = str(names[idx])
            if len(term) >= 3 and any(ch.isalpha() for ch in term):
                ranked.append(term)
        return ranked


MiniLMTextFeatures.__module__ = "train_ml"
if __name__ == "__main__":
    sys.modules.setdefault("train_ml", sys.modules[__name__])
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# ---------- General: multi-encoding fallback CSV reader ----------
def read_csv_any(path, **kwargs):
    """Try standard encodings in order; latin-1 never raises UnicodeDecodeError, so decoding always succeeds."""
    import pandas as pd
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc, **kwargs)
        except UnicodeDecodeError:
            continue
    raise RuntimeError(f"Unable to decode file: {path}")


# ---------- Label normalization: ham -> 0, spam/smishing/etc. -> 1 ----------
def norm_label(x):
    x = str(x).strip().lower()
    if x in ("ham", "normal", "legitimate", "legit", "0"):
        return 0
    if x in ("spam", "smishing", "scam", "fraud", "phishing", "1"):
        return 1
    return None


# ---------- 1. SMSSpamCollection.txt (TSV, no header) ----------
def load_smsspamcollection(path):
    df = read_csv_any(path, sep="\t", names=["label", "message"])
    df["label"] = df["label"].map(norm_label)
    return df[["message", "label"]]


# ---------- 2. SMSSpamCollection2.txt (CSV, with header LABEL,TEXT,...) ----------
def load_smsspamcollection2(path):
    df = read_csv_any(path, on_bad_lines="skip")
    df = df.rename(columns={"LABEL": "label", "TEXT": "message"})
    df["label"] = df["label"].map(norm_label)
    return df[["message", "label"]]


def build_pipeline():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    return Pipeline([
        ("features", MiniLMTextFeatures()),
        ("classifier", LogisticRegression(C=10, max_iter=5000)),
    ])


def main():
    import joblib
    import pandas as pd
    from sklearn.metrics import classification_report, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(current_dir, "scamlens_ml")
    os.makedirs(model_dir, exist_ok=True)

    sources = [
        ("SMSSpamCollection.txt",  load_smsspamcollection),
        ("SMSSpamCollection2.txt", load_smsspamcollection2),
    ]

    frames = []
    for name, loader in sources:
        p = os.path.join(current_dir, name)
        if not os.path.exists(p):
            print(f"[SKIP] {name} does not exist")
            continue
        part = loader(p)
        part = part.dropna(subset=["message", "label"])
        part["message"] = part["message"].astype(str).str.strip()
        part = part[part["message"] != ""]
        print(f"[OK] {name}: {len(part)} records")
        frames.append(part)

    if not frames:
        raise SystemExit("No training data available.")

    df = pd.concat(frames, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates(subset=["message"]).reset_index(drop=True)
    df["label"] = df["label"].astype(int)

    print("\n===== After merging =====")
    print(f"Record count before deduplication: {before}")
    print(f"Record count after deduplication:  {len(df)} (removed {before - len(df)} duplicates)")
    print(df["label"].value_counts().rename({0: "ham(0)", 1: "spam(1)"}))

    print("\nTraining model (all-MiniLM-L6-v2 + TF-IDF + Logistic Regression)...")
    X_tr, X_te, y_tr, y_te = train_test_split(
        df["message"], df["label"],
        test_size=0.2, random_state=42, stratify=df["label"]
    )

    eval_pipeline = build_pipeline()
    eval_pipeline.fit(X_tr, y_tr)
    probs = eval_pipeline.predict_proba(X_te)[:, 1]
    preds = (probs >= 0.5).astype(int)

    print("\n===== Validation set evaluation (20% held-out) =====")
    print(classification_report(y_te, preds, target_names=["ham", "spam"], digits=4))
    print(f"ROC-AUC: {roc_auc_score(y_te, probs):.4f}")

    print("Retraining on the full dataset...")
    final_pipeline = build_pipeline()
    final_pipeline.fit(df["message"], df["label"])

    features = final_pipeline.named_steps["features"]
    classifier = final_pipeline.named_steps["classifier"]
    classifier.feature_log_prob_ = np.vstack([-classifier.coef_[0], classifier.coef_[0]])

    # predict.py expects these two step names; the classifier stays a real
    # LogisticRegression but advertises feature_log_prob_ for compatibility.
    model = Pipeline([
        ("tfidfvectorizer", features),
        ("multinomialnb", classifier),
    ])

    model_path = os.path.join(model_dir, "model.pkl")
    joblib.dump(model, model_path, compress=3)
    print(f"\n✅ Model training complete. Saved to {model_path}")


if __name__ == "__main__":
    main()