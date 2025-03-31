# ------------- src/password_generator.py -------------
import secrets
import string
import re
import math # Needed for entropy calculation
import random # Needed for l33tspeak
from typing import List, Dict, Optional
from dataclasses import dataclass, field

@dataclass
class PasswordSuggestion:
    password: str
    description: str
    entropy: float = field(init=False) # Calculated after init
    memorable: bool = False # Default, can be overridden

    def __post_init__(self):
        # Calculate entropy after password is set
        self.entropy = self._calculate_entropy(self.password)

    def _calculate_entropy(self, password: str) -> float:
        """Estimates entropy based on character set size."""
        if not password:
            return 0.0
        char_sets = 0
        if any(c in string.ascii_lowercase for c in password): char_sets += 26
        if any(c in string.ascii_uppercase for c in password): char_sets += 26
        if any(c in string.digits for c in password): char_sets += 10
        # Use a fixed estimate for special chars pool size
        if any(c in string.punctuation + ' ' for c in password): char_sets += 32
        if char_sets == 0: return 0.0 # Avoid log2(0)
        return len(password) * math.log2(char_sets)

class PasswordGenerator:
    def __init__(self, policy_manager):
        """
        Initializes the Password Generator.
        Args:
            policy_manager (PolicyManager): An instance to access policy requirements.
        """
        self.policy_manager = policy_manager
        self.policy = self.policy_manager.get_policy()
        self.char_sets = {
            'upper': string.ascii_uppercase,
            'lower': string.ascii_lowercase,
            'digits': string.digits,
            'special': self.policy.get('special_chars', string.punctuation) # Use policy special chars
        }
        self.all_chars = "".join(self.char_sets.values())
        # Basic l33tspeak mapping
        self.l33t_map = {'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$', 't': '7'}


    def _meets_policy(self, password: str) -> bool:
        """Checks if a generated password meets the policy requirements."""
        policy = self.policy # Use cached policy
        special_chars_pattern = f'[{self.policy_manager.get_special_chars_regex()}]'

        if len(password) < policy['min_length']: return False
        if policy['require_lower'] and not re.search(r'[a-z]', password): return False
        if policy['require_upper'] and not re.search(r'[A-Z]', password): return False
        if policy['require_digits'] and not re.search(r'\d', password): return False
        if policy['require_special'] and not re.search(special_chars_pattern, password): return False
        return True

    def generate_complex_password(self, length: Optional[int] = None) -> str:
        """Generates a high-entropy complex password meeting policy."""
        if length is None:
            length = max(self.policy['min_length'], 20) # Ensure decent length

        attempts = 0
        while attempts < 100: # Prevent infinite loops
            chars = []
            # Ensure required characters are included first if policy dictates
            if self.policy['require_lower']: chars.append(secrets.choice(self.char_sets['lower']))
            if self.policy['require_upper']: chars.append(secrets.choice(self.char_sets['upper']))
            if self.policy['require_digits']: chars.append(secrets.choice(self.char_sets['digits']))
            if self.policy['require_special']: chars.append(secrets.choice(self.char_sets['special']))

            # Fill remaining length
            remaining_length = length - len(chars)
            if remaining_length > 0:
                chars.extend(secrets.choice(self.all_chars) for _ in range(remaining_length))

            # Shuffle thoroughly
            random.shuffle(chars)
            password = "".join(chars)

            # Verify policy compliance
            if self._meets_policy(password):
                return password
            attempts += 1
        # Fallback if policy not met after many attempts (should be rare)
        return "ErrorGeneratingComplexPassword"


    def generate_transformed_password(self, base_word: str = "TransformMe") -> str:
        """Generates a password by applying l33tspeak and adding complexity."""
        length = max(self.policy['min_length'], 16) # Target length

        # Apply l33tspeak
        transformed = "".join(self.l33t_map.get(c.lower(), c) for c in base_word)

        # Ensure policy requirements by adding missing types
        current_len = len(transformed)
        required_adds = []
        if self.policy['require_lower'] and not any(c in self.char_sets['lower'] for c in transformed):
             required_adds.append(secrets.choice(self.char_sets['lower']))
        if self.policy['require_upper'] and not any(c in self.char_sets['upper'] for c in transformed):
             required_adds.append(secrets.choice(self.char_sets['upper']))
        if self.policy['require_digits'] and not any(c in self.char_sets['digits'] for c in transformed):
             required_adds.append(secrets.choice(self.char_sets['digits']))
        if self.policy['require_special'] and not any(c in self.char_sets['special'] for c in transformed):
             required_adds.append(secrets.choice(self.char_sets['special']))

        # Fill remaining length randomly, prioritizing required additions
        fill_len = length - current_len - len(required_adds)
        random_fill = [secrets.choice(self.all_chars) for _ in range(max(0, fill_len))]

        # Combine and shuffle
        combined = list(transformed) + required_adds + random_fill
        random.shuffle(combined)
        password = "".join(combined)

        # Ensure minimum length again after shuffling/potential shortening
        while len(password) < self.policy['min_length']:
             password += secrets.choice(self.all_chars)

        # Final policy check (optional but safe)
        if self._meets_policy(password):
             return password[:length] # Trim if needed
        else:
             # Fallback to complex if transform fails policy
             return self.generate_complex_password(length)


    def generate_suggestions(self, base_password_info: Optional[Dict] = None) -> List[PasswordSuggestion]:
        """
        Generates a list of diverse password suggestions meeting policy.
        Args:
            base_password_info (dict, optional): Analysis info of the user's weak password.
                                                 Currently unused but could guide generation.
        """
        suggestions = []
        target_length = max(self.policy['min_length'], 16) # Sensible default length

        # Suggestion 1: High-entropy complex password
        complex_pwd = self.generate_complex_password(target_length + 4) # Make it longer
        suggestions.append(PasswordSuggestion(
            password=complex_pwd,
            description="Option 1: Highly complex and random"
        ))

        # Suggestion 2: Transformed common word example
        # In a real scenario, could pick a word related to context or policy
        transformed_pwd = self.generate_transformed_password("SecurePass")
        suggestions.append(PasswordSuggestion(
            password=transformed_pwd,
            description="Option 2: Transformed word with added complexity",
            memorable=True # Potentially more memorable than pure random
        ))

        # Suggestion 3: Another complex password (different length/structure)
        complex_pwd_2 = self.generate_complex_password(target_length)
        # Ensure it's different from the first one
        while complex_pwd_2 == complex_pwd:
            complex_pwd_2 = self.generate_complex_password(target_length)
        suggestions.append(PasswordSuggestion(
            password=complex_pwd_2,
            description="Option 3: Another complex random password"
        ))

        # Filter out any suggestions that might have failed generation
        valid_suggestions = [s for s in suggestions if not s.password.startswith("ErrorGenerating")]

        # Ensure suggestions meet entropy policy (redundant if _meets_policy includes it)
        min_entropy = self.policy.get('min_entropy', 0)
        final_suggestions = [s for s in valid_suggestions if s.entropy >= min_entropy]

        # If somehow no suggestions meet policy, generate one guaranteed complex one
        if not final_suggestions:
             final_suggestions.append(PasswordSuggestion(
                  password=self.generate_complex_password(target_length),
                  description="Fallback: Guaranteed complex password"
             ))

        return final_suggestions[:3] # Return top 3 valid suggestions

# Example usage:
if __name__ == '__main__':
    import re # Import re here for example usage context
    from policy_manager import PolicyManager
    manager = PolicyManager()
    generator = PasswordGenerator(manager)

    print("--- Generating Suggestions ---")
    suggestions = generator.generate_suggestions()
    for i, sug in enumerate(suggestions):
        print(f"Suggestion {i+1}: {sug.password}")
        print(f"  Description: {sug.description}")
        print(f"  Entropy: {sug.entropy:.1f} bits")
        print(f"  Memorable: {sug.memorable}")
        print(f"  Meets Policy: {generator._meets_policy(sug.password)}") # Verify policy