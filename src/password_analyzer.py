# ------------- src/password_analyzer.py -------------
import re
import joblib
from collections import defaultdict
import os
# Consider using a dedicated library for more robust pattern detection:
# from zxcvbn import zxcvbn # Example: requires 'pip install zxcvbn'

class PasswordAnalyzer:
    def __init__(self, policy_manager):
        self.policy_manager = policy_manager
        # Ensure model paths are correct relative to the execution context
        model_path = 'models/password_classifier.pkl'
        tfidf_path = 'models/tfidf_vectorizer.pkl'

        if not os.path.exists(model_path) or not os.path.exists(tfidf_path):
             raise FileNotFoundError("ML model or TFIDF vectorizer not found. Run train_model.py first.")

        try:
            self.model = joblib.load(model_path)
            self.tfidf = joblib.load(tfidf_path)
        except Exception as e:
            raise IOError(f"Error loading ML model/vectorizer: {e}")

        # Basic common patterns (expand as needed)
        self.common_patterns = [
            (r'[a-z]{4,}\d{1,4}$', 'Common pattern: word followed by numbers'),
            (r'^[A-Z][a-z]+\d+$', 'Common pattern: capitalized word with numbers'),
            (r'^(.)\1+$', 'Pattern: repeated single character'), # e.g., 'aaaaa'
            (r'(.)\1{2,}', 'Pattern: 3+ repeated characters'), # e.g., 'passs'
            (r'123|234|345|456|567|678|789|abc|qwe|asd|zxc', 'Pattern: common sequence')
        ]
        # Basic dictionary (replace with a proper dictionary file approach)
        self.basic_dictionary = {'password', 'admin', 'root', 'user', 'test', 'qwerty', '123456'}

    def conventional_checks(self, password):
        """Performs checks based on the loaded policy."""
        policy = self.policy_manager.get_policy()
        special_chars_pattern = f'[{self.policy_manager.get_special_chars_regex()}]'

        checks = {
            'Length': len(password) >= policy['min_length'],
            'Lowercase': (not policy['require_lower']) or bool(re.search(r'[a-z]', password)),
            'Uppercase': (not policy['require_upper']) or bool(re.search(r'[A-Z]', password)),
            'Digit': (not policy['require_digits']) or bool(re.search(r'\d', password)),
            'Special': (not policy['require_special']) or bool(re.search(special_chars_pattern, password))
        }
        # Rename keys for consistency before returning
        policy_checks = {k:v for k,v in checks.items()} # Keep original names for internal use
        checks = { # Rename for final output consistency if needed elsewhere
            'length': checks['Length'],
            'lower': checks['Lowercase'],
            'upper': checks['Uppercase'],
            'digit': checks['Digit'],
            'special': checks['Special'],
        }
        checks['all_passed'] = all(checks.values())
        return checks, policy_checks # Return both for detailed feedback

    def detect_common_patterns(self, password):
        """Detects predefined common patterns."""
        patterns_found = []
        for pattern, msg in self.common_patterns:
            # Use re.IGNORECASE for broader matching if needed
            if re.search(pattern, password, re.IGNORECASE):
                patterns_found.append(msg)
        return patterns_found

    # --- Placeholder Pattern Detections ---
    # Replace these with more robust implementations, potentially using libraries like zxcvbn

    def detect_keyboard_patterns(self, password):
        """Placeholder for keyboard pattern detection (e.g., qwerty, asdf)."""
        # Basic example check
        patterns = ['qwerty', 'asdfgh', 'zxcvbn', '1234567890']
        found = []
        for pattern in patterns:
             if pattern in password.lower():
                  found.append(f"Keyboard pattern: '{pattern}'")
        return found

    def detect_sequences(self, password):
        """Placeholder for sequence detection (e.g., abc, 123, 987)."""
        found = []
        if re.search(r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz', password.lower()):
            found.append("Sequential letters (e.g., 'abc')")
        if re.search(r'123|234|345|456|567|678|789|890', password):
             found.append("Sequential digits (e.g., '123')")
        # Add reverse sequences if needed
        return found

    def detect_date_patterns(self, password):
        """Placeholder for date pattern detection (e.g., 1999, 2024, 0101)."""
        # Basic regex for year-like numbers or simple repeats
        found = []
        if re.search(r'\b(19[89]\d|20[0-2]\d)\b', password): # Matches years 1980-2029
            found.append("Contains a year-like number")
        if re.search(r'(\d)\1{3}', password): # Matches '1111', '0000' etc.
            found.append("Contains repeated digits (e.g., '1111')")
        return found

    def detect_dictionary_words(self, password):
        """Placeholder for dictionary word detection."""
        # Very basic check against a small set
        found = []
        for word in self.basic_dictionary:
            if word in password.lower():
                found.append(f"Contains common word: '{word}'")
        # For production: use a large dictionary file and check substrings/variations
        return found

    # --- End Placeholder Pattern Detections ---

    def analyze_password(self, password):
        """Performs comprehensive password analysis."""
        result = defaultdict(dict)
        policy = self.policy_manager.get_policy()

        # 1. Conventional Policy Checks
        policy_checks_met, detailed_policy_checks = self.conventional_checks(password)
        result['policy_checks'] = policy_checks_met
        result['detailed_policy_checks'] = detailed_policy_checks # Store detailed results

        # 2. Pattern Analysis
        common = self.detect_common_patterns(password)
        keyboard = self.detect_keyboard_patterns(password)
        sequences = self.detect_sequences(password)
        dates = self.detect_date_patterns(password)
        dictionary = self.detect_dictionary_words(password)
        all_patterns = common + keyboard + sequences + dates + dictionary
        result['pattern_analysis'] = {
            'patterns_found': all_patterns,
            'character_diversity': len(set(password)) / len(password) if password else 0
        }

        # 3. Machine Learning Analysis
        try:
            # Ensure password is not empty before transform
            if password:
                X = self.tfidf.transform([password])
                proba = self.model.predict_proba(X)[0]
                ml_score = float(proba[1])
                ml_strong = ml_score > 0.7 # Adjust threshold based on evaluation
            else:
                ml_score = 0.0
                ml_strong = False

            result['ml_analysis'] = {
                'strength_score': ml_score,
                'is_strong_prediction': ml_strong # Model's prediction
            }
        except Exception as e:
            print(f"ML Analysis Error: {e}")
            result['ml_analysis'] = {
                'strength_score': 0.0,
                'is_strong_prediction': False,
                'error': str(e)
            }

        return dict(result)

# Example usage:
if __name__ == '__main__':
    from policy_manager import PolicyManager
    manager = PolicyManager()
    analyzer = PasswordAnalyzer(manager)
    test_passwords = ["password123", "Qwert!", "MyStr0ngP@sswOrd", "Summer2024!", "aaaaaaaaa", "12345"]
    for pwd in test_passwords:
        print(f"\n--- Analyzing: {pwd} ---")
        analysis = analyzer.analyze_password(pwd)
        import json
        print(json.dumps(analysis, indent=2))