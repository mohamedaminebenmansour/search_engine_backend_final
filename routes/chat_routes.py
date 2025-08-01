from flask import Blueprint, request, jsonify, current_app
from services.chat_service import ChatService
from utils.auth_utils import decode_jwt
from models.user_model import User

chat_bp = Blueprint("chat", __name__)

@chat_bp.route('/chat', methods=['POST', 'OPTIONS'])
def chat():
    if request.method == 'OPTIONS':
        current_app.logger.debug("Received OPTIONS request for /chat")
        return jsonify({}), 200

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Requête JSON manquante"}), 400

        auth_header = request.headers.get('Authorization')
        current_user = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                user_id_from_token = decode_jwt(token)
                current_user = User.query.filter_by(id=user_id_from_token).first()
                if not current_user:
                    return jsonify({"error": "Token invalide"}), 401
            except Exception as e:
                current_app.logger.error(f"Token decoding failed: {str(e)}")
                pass

        result, status = ChatService.process_chat(data, current_user)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Internal server error: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500