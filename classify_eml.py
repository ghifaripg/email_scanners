import email
from email import policy
from email.parser import BytesParser
import joblib
import re
import numpy as np
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import nltk
import sys
import os
import requests
from tqdm import tqdm

# One-time NLTK data download (safe to call every time)
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

# File paths
SVM_MODEL_PATH = "svm_word2vec_model.pkl"
W2V_MODEL_PATH = "word2vec_model.pkl"

# Download word2vec model from Google Drive if missing
def download_word2vec():
    if not os.path.exists(W2V_MODEL_PATH):
        print("📦 Downloading word2vec_model.pkl...")
        url = "https://drive.usercontent.google.com/download?id=1ZSfZ7p66lcaLX5t574pp-uMqknQfudfF&export=download"
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get("content-length", 0))
        block_size = 1024
        with open(W2V_MODEL_PATH, "wb") as f, tqdm(
            desc="Downloading", total=total_size, unit="B", unit_scale=True
        ) as bar:
            for data in response.iter_content(block_size):
                bar.update(len(data))
                f.write(data)

# Ensure both models exist
if not os.path.exists(SVM_MODEL_PATH):
    raise FileNotFoundError(f"{SVM_MODEL_PATH} is missing. Please upload or place it in the app directory.")

download_word2vec()

# Load models
clf = joblib.load(SVM_MODEL_PATH)
w2v_model = joblib.load(W2V_MODEL_PATH)

# Preprocessing function
stop_words = set(stopwords.words('english'))
def preprocess(text):
    text = re.sub(r'\W+', ' ', text.lower())
    words = word_tokenize(text)
    return [w for w in words if w not in stop_words]

# Vectorization function
def vectorize(tokens):
    vectors = [w2v_model[w] for w in tokens if w in w2v_model]
    if not vectors:
        return np.zeros(300)
    return np.mean(vectors, axis=0)

# Extract subject + body from .eml
def extract_eml_text(eml_path):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg['subject'] or ''
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    return subject + ' ' + body

# Run classification
def classify_eml(eml_path):
    text = extract_eml_text(eml_path)
    tokens = preprocess(text)
    vec = vectorize(tokens).reshape(1, -1)
    prediction = clf.predict(vec)[0]
    proba = clf.predict_proba(vec)[0][int(prediction)]
    return prediction, proba

# CLI usage
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python classify_eml.py path/to/email.eml")
        sys.exit(1)

    path = sys.argv[1]
    label, confidence = classify_eml(path)

    result = "Phishing/Spam" if label == 1 else "Legitimate"
    print(f"\n📧 Prediction: {result}")
    print(f"📈 Confidence: {confidence:.2f}")
