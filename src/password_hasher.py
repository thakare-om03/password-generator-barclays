import bcrypt
import secrets
import base64
from typing import Tuple, Optional

class PasswordHasher:
    ROUNDS = 12  # Configurable work factor

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt with a secure random salt"""
        salt = bcrypt.gensalt(rounds=PasswordHasher.ROUNDS)
        password_hash = bcrypt.hashpw(password.encode(), salt)
        return password_hash.decode()

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False

    @staticmethod
    def generate_reset_token() -> Tuple[str, str]:
        """Generate a secure password reset token and its hash"""
        token = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode()
        return token, token_hash