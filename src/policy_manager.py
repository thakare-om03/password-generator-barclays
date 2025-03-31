# ------------- src/policy_manager.py -------------
import yaml
import os

class PolicyManager:
    def __init__(self, policy_file='config/policy.yml'):
        self.policy_file = policy_file
        self.policy = self._load_policy()

    def _load_policy(self):
        """Loads the policy from the YAML file."""
        default_policy = {
            'min_length': 12,
            'require_upper': True,
            'require_lower': True,
            'require_digits': True,
            'require_special': True,
            'max_breach_count': 0,
            'min_entropy': 60,
            'special_chars': '!@#$%^&*(),.?":{}|<>'
        }
        if not os.path.exists(self.policy_file):
            print(f"Warning: Policy file '{self.policy_file}' not found. Using default policy.")
            return default_policy
        try:
            with open(self.policy_file, 'r') as f:
                config = yaml.safe_load(f)
                # Merge loaded policy with defaults to ensure all keys exist
                policy = default_policy.copy()
                if config and 'password_policy' in config:
                    policy.update(config['password_policy'])
                else:
                     print(f"Warning: 'password_policy' key not found in '{self.policy_file}'. Using default policy.")
                return policy
        except Exception as e:
            print(f"Error loading policy file '{self.policy_file}': {e}. Using default policy.")
            return default_policy

    def get_policy(self):
        """Returns the currently loaded policy."""
        return self.policy

    def get_special_chars_regex(self):
        """Returns a regex-safe string of allowed special characters."""
        return ''.join(f'\\{c}' if c in r'.^$*+?{}[]\|()-' else c for c in self.policy.get('special_chars', ''))

# Example usage:
if __name__ == '__main__':
    manager = PolicyManager()
    print("Loaded Policy:", manager.get_policy())
    print("Special Chars Regex:", manager.get_special_chars_regex())