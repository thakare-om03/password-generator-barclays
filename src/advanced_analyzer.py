# ------------- src/advanced_analyzer.py -------------
import torch
# Check if transformers is installed and provide guidance if not
try:
    from transformers import AutoModel, AutoTokenizer
except ImportError:
    raise ImportError("The 'transformers' library is not installed. Please install it using 'pip install transformers'. You might also need 'torch' or 'tensorflow'.")

import math
import re
import hashlib
import requests
import logging # Use logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

@dataclass
class SecurityMetrics:
    entropy: float
    crack_time_estimates: Dict[str, str]
    breach_count: int
    policy_compliant: bool = False # Added policy compliance flag
    # complexity_score: Optional[float] = None # Keep if BERT complexity is used reliably
    policy_violations: List[str] = field(default_factory=list) # List reasons for non-compliance

class AdvancedPasswordAnalyzer:
    def __init__(self, policy_manager):
        """
        Initializes the Advanced Password Analyzer.
        Args:
            policy_manager (PolicyManager): Instance to access policy thresholds.
        """
        self.policy_manager = policy_manager
        self.estimator = SecurityEstimator()
        # BERT model loading is optional and resource-intensive. Consider removing if not crucial.
        # self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        # try:
        #     self.model = AutoModel.from_pretrained("bert-base-uncased").to(self.device)
        #     self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        #     self.bert_enabled = True
        #     logging.info(f"BERT model loaded successfully on {self.device}.")
        # except Exception as e:
        #     logging.warning(f"Could not load BERT model ('bert-base-uncased'): {e}. AI entropy estimation will be disabled.")
        #     self.model = None
        #     self.tokenizer = None
        #     self.bert_enabled = False
        self.bert_enabled = False # Disable BERT by default for simplicity/performance

    def analyze_password(self, password: str) -> SecurityMetrics:
        """Performs advanced analysis: entropy, crack time, breach check, policy compliance."""
        policy = self.policy_manager.get_policy()

        # Calculate entropy (use base or AI-enhanced)
        # base_entropy = self.calculate_base_entropy(password)
        # if self.bert_enabled:
        #     entropy = self.ai_entropy_estimation(password, base_entropy)
        #     complexity_score = entropy / base_entropy - 1 if base_entropy > 0 else 0 # Approx. complexity factor
        # else:
        entropy = self.calculate_base_entropy(password)
            # complexity_score = None

        # Estimate crack times
        crack_times = self.estimator.estimate_crack_time(entropy)

        # Check Pwned Passwords API
        breach_count = self.check_pwned(password)

        # Check compliance against advanced policy thresholds
        violations = []
        meets_entropy = entropy >= policy.get('min_entropy', 0)
        meets_breach = breach_count <= policy.get('max_breach_count', 0)

        if not meets_entropy:
            violations.append(f"Entropy ({entropy:.1f} bits) is below minimum ({policy.get('min_entropy', 0)} bits)")
        if not meets_breach:
            violations.append(f"Found in {breach_count} breaches (policy allows max {policy.get('max_breach_count', 0)})")

        policy_compliant = meets_entropy and meets_breach

        return SecurityMetrics(
            entropy=entropy,
            crack_time_estimates=crack_times,
            breach_count=breach_count,
            policy_compliant=policy_compliant,
            policy_violations=violations
            # complexity_score=complexity_score # Include if BERT is used
        )

    def ai_entropy_estimation(self, password: str, base_entropy: float) -> float:
        """(Optional) Uses BERT attention std dev to adjust base entropy."""
        if not self.bert_enabled or not password:
            return base_entropy
        try:
            inputs = self.tokenizer(password, return_tensors="pt").to(self.device)
            # Ensure model is in eval mode and use no_grad for inference
            self.model.eval()
            with torch.no_grad():
                outputs = self.model(**inputs, output_attentions=True)

            # Use attention from the last layer, average across heads
            # Detach from graph and move to CPU before numpy conversion
            attention_std_dev = outputs.attentions[-1].mean(dim=1).detach().cpu().numpy().std()

            # Apply a scaling factor based on attention std dev. Needs careful tuning.
            # This is a heuristic and may not be robust.
            complexity_factor = 1 + min(max(attention_std_dev * 10, 0), 1) # Example scaling
            return base_entropy * complexity_factor
        except Exception as e:
            logging.warning(f"Error during AI entropy estimation: {e}. Falling back to base entropy.")
            return base_entropy

    def calculate_base_entropy(self, password: str) -> float:
        """Calculates Shannon entropy based on assumed character set size."""
        if not password:
            return 0.0

        pool_size = 0
        special_chars = self.policy_manager.get_special_chars_regex() # Use policy special chars
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'\d', password): pool_size += 10
        if re.search(f'[{special_chars}]', password):
             pool_size += len(self.policy_manager.policy.get('special_chars', '')) # Use actual count from policy

        if pool_size == 0: return 0.0
        # Avoid log2(0) or log2(1) issues
        if pool_size <= 1: return 0.0

        return len(password) * math.log2(pool_size)

    def check_pwned(self, password: str) -> int:
        """Checks password against Have I Been Pwned API v3."""
        if not password:
            return 0
        try:
            # Hash the password using SHA-1 (as required by the API)
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]

            # Make the API request
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'Add-Padding': 'true'} # Recommended by HIBP API v3
            response = requests.get(url, headers=headers, timeout=5) # Added timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Process the response
            hashes = response.text.splitlines()
            for line in hashes:
                line_suffix, count_str = line.split(':')
                if line_suffix == suffix:
                    return int(count_str)
            return 0 # Suffix not found

        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not check Pwned Passwords API: {e}")
            return -1 # Indicate an error occurred during lookup
        except ValueError:
             logging.warning(f"Invalid response format from Pwned Passwords API.")
             return -1 # Indicate an error
        except Exception as e:
             logging.error(f"Unexpected error checking Pwned Passwords: {e}", exc_info=True)
             return -1 # Indicate an error

class SecurityEstimator:
    def __init__(self):
        # Realistic estimates (adjust based on current hardware benchmarks)
        # Speeds in hashes per second for common algorithms like NTLM or MD5.
        # Bcrypt/Scrypt are much slower. These times are illustrative of potential
        # risk if a *weaker* hash (like SHA1 of the password) were exposed.
        self.hashcat_speeds = {
            'Online Attack (Slow)': 10,           # e.g., Rate limited login attempts
            'Offline Attack (Single GPU)': 1e9,   # e.g., Mid-range GPU cracking faster hashes
            'Offline Attack (GPU Farm)': 1e12,    # e.g., Dedicated cracking rigs
        }
        self.seconds_in_year = 31536000

    def estimate_crack_time(self, entropy: float) -> Dict[str, str]:
        """Estimates crack time based on entropy for different attack scenarios."""
        if entropy <= 0:
             return {scenario: "Instant" for scenario in self.hashcat_speeds}

        combinations = 2 ** entropy
        estimates = {}
        for scenario, speed in self.hashcat_speeds.items():
            if speed <= 0: continue # Avoid division by zero
            seconds_to_crack = combinations / speed
            # Provide human-readable estimates
            if seconds_to_crack < 60:
                time_str = f"{seconds_to_crack:.1f} seconds"
            elif seconds_to_crack < 3600:
                time_str = f"{seconds_to_crack / 60:.1f} minutes"
            elif seconds_to_crack < 86400:
                time_str = f"{seconds_to_crack / 3600:.1f} hours"
            elif seconds_to_crack < self.seconds_in_year:
                 time_str = f"{seconds_to_crack / 86400:.1f} days"
            else:
                 years = seconds_to_crack / self.seconds_in_year
                 time_str = f"{years:.1e} years" # Use scientific notation for very long times
            estimates[scenario] = time_str
        return estimates

# Example usage:
if __name__ == '__main__':
    import sys # Import sys here for example usage context
    from policy_manager import PolicyManager
    manager = PolicyManager()
    analyzer = AdvancedPasswordAnalyzer(manager)
    test_passwords = ["password", "MyStr0ngP@sswOrd", "Summer2024!", "Tr0ub4dor&3", sys.argv[1] if len(sys.argv) > 1 else "ComplexP@ssw0rdExample!"] # Allows testing via CLI arg
    for pwd in test_passwords:
        print(f"\n--- Analyzing Advanced: {pwd} ---")
        metrics = analyzer.analyze_password(pwd)
        print(f"  Entropy: {metrics.entropy:.2f} bits")
        print(f"  Breach Count: {metrics.breach_count if metrics.breach_count != -1 else 'Error checking API'}")
        print(f"  Policy Compliant (Advanced): {metrics.policy_compliant}")
        if metrics.policy_violations:
             print(f"  Policy Violations:")
             for v in metrics.policy_violations:
                  print(f"    - {v}")
        print(f"  Crack Time Estimates:")
        for scenario, time_str in metrics.crack_time_estimates.items():
             print(f"    - {scenario}: {time_str}")