import os
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

current_dir = os.path.dirname(os.path.abspath(__file__))


def read_csv_any(path, **kwargs):
    """Read a CSV file trying multiple encodings until one succeeds."""
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc, **kwargs)
        except UnicodeDecodeError:
            continue
    raise RuntimeError(f"Unable to decode file: {path}")


def norm_label(x):
    """Normalize label values to binary: 0 = legitimate, 1 = spam/phishing."""
    x = str(x).strip().lower()
    if x in ("ham", "normal", "legitimate", "legit", "0"):
        return 0
    if x in ("spam", "smishing", "scam", "fraud", "phishing", "1"):
        return 1
    return None


def collect_spam_texts():
    """Collect spam/smishing message texts from available dataset files."""
    texts = []

    # 1) SMSSpamCollection.txt
    p1 = os.path.join(current_dir, "SMSSpamCollection.txt")
    if os.path.exists(p1):
        df1 = read_csv_any(p1, sep="\t", names=["label", "message"])
        df1["label_n"] = df1["label"].map(norm_label)
        spam = df1.loc[df1["label_n"] == 1, "message"].astype(str).tolist()
        texts += spam
        print(f"[OK] SMSSpamCollection.txt: {len(spam)} spam samples loaded")

    # 2) SMSSpamCollection2.txt
    p2 = os.path.join(current_dir, "SMSSpamCollection2.txt")
    if os.path.exists(p2):
        df2 = read_csv_any(p2, on_bad_lines="skip")
        df2 = df2.rename(columns={"LABEL": "label", "TEXT": "message"})
        df2["label_n"] = df2["label"].map(norm_label)
        spam = df2.loc[df2["label_n"] == 1, "message"].astype(str).tolist()
        texts += spam
        print(f"[OK] SMSSpamCollection2.txt: {len(spam)} spam/smishing samples loaded")

    # Clean up: strip whitespace and drop empty entries
    texts = [t.strip() for t in texts if isinstance(t, str) and t.strip()]
    return texts


spam_texts = collect_spam_texts()
print(f"\nTotal spam/smishing samples collected: {len(spam_texts)}\n")

if not spam_texts:
    raise SystemExit("No spam/smishing samples were found.")

# ---------- Word frequency analysis ----------
vectorizer = CountVectorizer(stop_words="english", max_features=1000)
X = vectorizer.fit_transform(spam_texts)

word_counts = X.toarray().sum(axis=0)
words = vectorizer.get_feature_names_out()

freq_dict = dict(zip(words, word_counts))
sorted_words = sorted(freq_dict.items(), key=lambda item: item[1], reverse=True)

print("========================================")
print("Top 40 most frequent words in spam messages:")
print("========================================")
for word, count in sorted_words[:40]:
    print(f"{word}: {count} occurrences")