from datetime import datetime, timedelta
import jwt
from typing import Optional
import os

class SessionManager:
    def __init__(self):
        self.secret_key = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
        self.session_duration = timedelta(hours=24)
        
    def create_session(self, user_id: str, email: str, organization_id: str = None, role: str = None) -> str:
        """Create a new session token with organization context"""
        payload = {
            'user_id': user_id,
            'email': email,
            'organization_id': organization_id,
            'role': role,
            'exp': datetime.utcnow() + self.session_duration,
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def validate_session(self, token: str) -> Optional[dict]:
        """Validate session token and return payload if valid"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            if datetime.fromtimestamp(payload['exp']) < datetime.utcnow():
                return None
            return payload
        except jwt.InvalidTokenError:
            return None 