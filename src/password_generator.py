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
    def __init__(self, policy_manager, ai_explainer=None):
        """
        Initializes the Password Generator.
        Args:
            policy_manager (PolicyManager): An instance to access policy requirements.
            ai_explainer (AIExplainer, optional): Instance to use AI for suggestions.
        """
        self.policy_manager = policy_manager
        self.policy = self.policy_manager.get_policy()
        self.ai_explainer = ai_explainer  # Store the AI explainer instance
        self.char_sets = {
            'upper': string.ascii_uppercase,
            'lower': string.ascii_lowercase,
            'digits': string.digits,
            'special': self.policy.get('special_chars', string.punctuation) # Use policy special chars
        }
        self.all_chars = "".join(self.char_sets.values())
        # L33tspeak mapping for personalized suggestions
        self.l33t_map = {
            'a': ['@', '4', 'A'], 'b': ['8', 'B'], 'c': ['C', '('],
            'e': ['3', 'E'], 'g': ['9', 'G'], 'i': ['1', '!', 'I'],
            'l': ['1', 'L'], 'o': ['0', 'O'], 's': ['$', '5', 'S'],
            't': ['7', 'T'], 'z': ['2', 'Z'], 'u': ['U', 'ü']
        }

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

    def enhance_user_password(self, password: str, variation_level: float = 0.5) -> str:
        """
        Enhances user's password with substitutions and additions to make it policy-compliant
        and more secure while keeping it recognizable.
        
        Args:
            password: The user's original password
            variation_level: Controls how much to vary the output (0.0-1.0)
        """
        if not password:
            return self.generate_complex_password()
        
        # Make a copy of the password as a list to modify
        enhanced = list(password)
        
        # Apply l33tspeak substitutions with varying probability based on variation_level
        substitution_chance = 0.3 + variation_level * 0.5  # 30%-80% chance depending on variation
        for i, char in enumerate(enhanced):
            if char.lower() in self.l33t_map and random.random() < substitution_chance:
                enhanced[i] = random.choice(self.l33t_map[char.lower()])
        
        # Ensure policy requirements
        special_chars = self.policy.get('special_chars', '!@#$%^&*()')
        
        # Check if we need to add character types to meet policy
        has_lower = any(c.islower() for c in enhanced)
        has_upper = any(c.isupper() for c in enhanced)
        has_digit = any(c.isdigit() for c in enhanced)
        has_special = any(c in special_chars for c in enhanced)
        
        # Add missing character types
        if self.policy['require_lower'] and not has_lower:
            enhanced.append(random.choice(self.char_sets['lower']))
        if self.policy['require_upper'] and not has_upper:
            enhanced.append(random.choice(self.char_sets['upper']))
        if self.policy['require_digits'] and not has_digit:
            enhanced.append(random.choice(self.char_sets['digits']))
        if self.policy['require_special'] and not has_special:
            enhanced.append(random.choice(special_chars))
        
        # Add random characters based on variation_level
        extra_chars = int(variation_level * 5) + 1  # Add 1-6 chars based on variation
        for _ in range(extra_chars):
            enhanced.insert(random.randint(0, len(enhanced)), 
                          secrets.choice(self.all_chars))
        
        # Add some random characters to increase entropy and reach minimum length
        while len(enhanced) < self.policy['min_length']:
            enhanced.insert(random.randint(0, len(enhanced)), 
                          secrets.choice(self.all_chars))
        
        # Shuffle the added characters - vary the amount of shuffling based on variation_level
        if len(enhanced) > 8:
            # Select a variable number of positions to swap based on variation_level
            swaps = int(min(4, len(enhanced) // 3) * variation_level) + 1
            for _ in range(swaps):
                i, j = random.sample(range(len(enhanced)), 2)
                enhanced[i], enhanced[j] = enhanced[j], enhanced[i]
        
        return ''.join(enhanced)

    def generate_personalized_suggestions(self, original_password: str, original_analysis: Dict = None) -> List[PasswordSuggestion]:
        """
        Generates 3 personalized password suggestions based on user's password,
        with increasing levels of modification to ensure entropy variation.
        
        Now also attempts to use AI-based enhancement if available.
        """
        if not original_password:
            return []
            
        suggestions = []
        
        # Try AI-based enhancement first if available
        ai_enhancement = None
        if self.ai_explainer and original_analysis:
            ai_enhancement = self.ai_explainer.enhance_password(original_password, original_analysis)
            
        if ai_enhancement and self._meets_policy(ai_enhancement):
            suggestions.append(PasswordSuggestion(
                password=ai_enhancement,
                description="AI-Enhanced: Intelligently improved version of your password",
                memorable=True
            ))
        
        # Create three suggestions with increasing variation levels
        variation_levels = [0.2, 0.5, 0.8]  # Low, medium, high variation
        descriptions = [
            "Personalized: Light enhancement of your password",
            "Personalized: Moderate enhancement with better security",
            "Personalized: Significant enhancement with high security"
        ]
        
        for i, (level, desc) in enumerate(zip(variation_levels, descriptions)):
            enhanced = self.enhance_user_password(original_password, level)
            suggestions.append(PasswordSuggestion(
                password=enhanced,
                description=desc,
                memorable=True
            ))
        
        return suggestions

    def generate_transformed_password(self, base_word: str = "TransformMe") -> str:
        """Generates a password by applying l33tspeak and adding complexity."""
        length = max(self.policy['min_length'], 16) # Target length

        # Apply l33tspeak
        transformed = "".join(self.l33t_map.get(c.lower(), [c])[0] for c in base_word)

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
        Now returns both personalized (based on user input) and high-entropy suggestions.
        
        Args:
            base_password_info (dict, optional): Analysis info of the user's password.
        """
        suggestions = []
        target_length = max(self.policy['min_length'], 16) # Sensible default length
        
        # Get the original password if available
        original_password = ""
        if base_password_info and isinstance(base_password_info, dict):
            # Try to extract the password from analysis results
            original_password = base_password_info.get('original_password', '')
        
        # Generate personalized suggestions based on user's password
        if original_password:
            personalized = self.generate_personalized_suggestions(original_password, base_password_info)
            suggestions.extend(personalized)
            
        # Generate high-entropy complex passwords
        # Suggestion 1: High-entropy complex password
        complex_pwd = self.generate_complex_password(target_length + 4) # Make it longer
        suggestions.append(PasswordSuggestion(
            password=complex_pwd,
            description="High-entropy: Complex and random"
        ))

        # Suggestion 2: Transformed common word example
        transformed_pwd = self.generate_transformed_password("SecurePass")
        suggestions.append(PasswordSuggestion(
            password=transformed_pwd,
            description="High-entropy: Transformed with complexity"
        ))

        # Suggestion 3: Another complex password (different length/structure)
        complex_pwd_2 = self.generate_complex_password(target_length)
        # Ensure it's different from the first one
        while complex_pwd_2 == complex_pwd:
            complex_pwd_2 = self.generate_complex_password(target_length)
        suggestions.append(PasswordSuggestion(
            password=complex_pwd_2,
            description="High-entropy: Alternative random pattern"
        ))

        # Filter out any suggestions that might have failed generation
        valid_suggestions = [s for s in suggestions if not s.password.startswith("ErrorGenerating")]

        # Ensure suggestions meet entropy policy
        min_entropy = self.policy.get('min_entropy', 0)
        final_suggestions = [s for s in valid_suggestions if s.entropy >= min_entropy]

        # If somehow no suggestions meet policy, generate one guaranteed complex one
        if not final_suggestions:
             final_suggestions.append(PasswordSuggestion(
                  password=self.generate_complex_password(target_length),
                  description="Fallback: Guaranteed complex password"
             ))

        return final_suggestions[:6] # Return up to 6 valid suggestions (3 personalized + 3 complex)

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