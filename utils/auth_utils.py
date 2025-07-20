import jwt
from functools import wraps
from flask import request, jsonify
from models.user_model import User
from config import SECRET_KEY
from extensions import bcrypt
from datetime import datetime, timedelta

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.check_password_hash(hashed_password, password)

def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Utilisateur non trouvé'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expiré'}), 401
        except Exception:
            return jsonify({'error': 'Token invalide'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def decode_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        raise Exception("Token expiré.")
    except jwt.InvalidTokenError:
        raise Exception("Token invalide.")