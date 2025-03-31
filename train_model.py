# ------------- train_model.py -------------
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import random
from tqdm import tqdm # For progress indication

# --- Configuration ---
DATA_FILE = 'data/rockyou.txt' # Path to your RockYou dataset (or similar)
MODELS_DIR = 'models'
TEST_SIZE = 0.2
RANDOM_STATE = 42
# Number of strong examples to generate relative to weak ones
# Adjust this ratio based on performance evaluation
STRONG_EXAMPLE_RATIO = 0.5 # Generate 50% as many strong examples as weak ones found

# --- Helper Functions ---

def generate_strong_password(length=16):
    """Generates a reasonably strong password example."""
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    # Ensure at least one of each type (basic approach)
    pwd_list = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice('!@#$%^&*()')
    ]
    pwd_list += [random.choice(chars) for _ in range(length - len(pwd_list))]
    random.shuffle(pwd_list)
    return "".join(pwd_list)

def generate_tricky_weak_password():
    """Generates weak passwords that might look complex."""
    patterns = [
        ("Password", "123!"), ("Summer", "2024$"), ("Admin", "@Work"),
        ("QWERTY", "uiop"), ("asdf", "ghjk"), ("Change", "MeNow!")
    ]
    base, suffix = random.choice(patterns)
    # Apply simple substitutions
    l33t_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
    base_l33t = "".join(l33t_map.get(c.lower(), c) for c in base)
    if random.random() < 0.5:
        return base_l33t + suffix
    else:
        return base + suffix

# Load RockYou dataset and generate balanced examples
def load_and_prepare_data(max_weak_samples=200000): # Limit samples for faster training
    """Loads weak passwords, generates strong and tricky weak ones."""
    weak_passwords = []
    try:
        print(f"Loading weak passwords from {DATA_FILE}...")
        with open(DATA_FILE, 'r', errors='ignore') as f:
            for i, line in enumerate(tqdm(f, desc="Reading weak passwords")):
                if i >= max_weak_samples:
                    break
                pwd = line.strip()
                if 4 <= len(pwd) <= 32: # Filter unreasonable lengths
                     weak_passwords.append(pwd)
        print(f"Loaded {len(weak_passwords)} weak password samples.")
    except FileNotFoundError:
        print(f"Error: Dataset file '{DATA_FILE}' not found.")
        print("Please download a dataset like RockYou and place it in the 'data/' directory.")
        return None, None

    if not weak_passwords:
         print("No weak passwords loaded. Cannot train model.")
         return None, None

    num_weak = len(weak_passwords)
    num_strong_target = int(num_weak * STRONG_EXAMPLE_RATIO)
    num_tricky_weak_target = int(num_weak * 0.1) # Add 10% tricky weak examples

    print(f"Generating {num_strong_target} strong password examples...")
    strong_passwords = [generate_strong_password(random.randint(12, 24)) for _ in tqdm(range(num_strong_target), desc="Generating strong")]

    print(f"Generating {num_tricky_weak_target} tricky weak password examples...")
    tricky_weak_passwords = [generate_tricky_weak_password() for _ in tqdm(range(num_tricky_weak_target), desc="Generating tricky weak")]

    # Combine and label
    X = weak_passwords + tricky_weak_passwords + strong_passwords
    y = [0] * (num_weak + num_tricky_weak_target) + [1] * num_strong_target # 0 = weak, 1 = strong

    print(f"Total samples: {len(X)}, Weak: {num_weak + num_tricky_weak_target}, Strong: {num_strong_target}")

    # Shuffle data
    combined = list(zip(X, y))
    random.shuffle(combined)
    X, y = zip(*combined)

    return list(X), list(y)

# --- Feature Engineering (Potential Improvement Area) ---
# Consider adding explicit features beyond TF-IDF:
# - Password length
# - Character counts (upper, lower, digit, special)
# - Entropy score
# - Results from basic pattern checks (requires integrating parts of PasswordAnalyzer here)
# This would require changing the model input and potentially the model type (e.g., using a ColumnTransformer).

def train():
    """Loads data, trains TF-IDF and Logistic Regression model, saves artifacts."""
    X, y = load_and_prepare_data()
    if X is None:
        return

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y # Stratify helps with imbalanced data
    )
    print(f"Training set size: {len(X_train)}, Test set size: {len(X_test)}")

    # TF-IDF Vectorization
    # Using char_wb includes word boundaries which can be useful
    print("Fitting TF-IDF Vectorizer...")
    tfidf = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5), min_df=5, max_features=50000) # Tuned parameters
    X_train_tfidf = tfidf.fit_transform(X_train)
    X_test_tfidf = tfidf.transform(X_test)
    print("TF-IDF fitting complete.")
    print(f"TF-IDF Feature shape: {X_train_tfidf.shape}")

    # Model Training (Logistic Regression)
    print("Training Logistic Regression model...")
    # Increased C for potentially stronger regularization if needed, balanced class weight
    model = LogisticRegression(class_weight='balanced', max_iter=1000, C=1.0, solver='liblinear', random_state=RANDOM_STATE)
    model.fit(X_train_tfidf, y_train)
    print("Model training complete.")

    # Evaluate Model
    print("\n--- Model Evaluation ---")
    y_pred = model.predict(X_test_tfidf)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Weak', 'Strong']))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Cross-validation (optional, provides more robust score)
    # print("\nPerforming Cross-Validation...")
    # scores = cross_val_score(model, X_train_tfidf, y_train, cv=5, scoring='accuracy')
    # print(f"Cross-Validation Accuracy: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")


    # Save artifacts
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)

    model_path = os.path.join(MODELS_DIR, 'password_classifier.pkl')
    tfidf_path = os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl')

    joblib.dump(model, model_path)
    joblib.dump(tfidf, tfidf_path)
    print(f"\nModel saved to {model_path}")
    print(f"TF-IDF Vectorizer saved to {tfidf_path}")

if __name__ == '__main__':
    # Import necessary libraries here if run as script
    import string
    train()