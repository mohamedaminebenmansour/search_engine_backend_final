from flask import request, jsonify, Blueprint, current_app, redirect, url_for
from services.auth_service import AuthService
from utils.auth_utils import token_required
from authlib.integrations.flask_client import OAuth

auth_bp = Blueprint('auth', __name__)

# Initialize OAuth
oauth = OAuth()

def init_auth_routes(app):
    oauth.init_app(app)

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /register")
        return jsonify({}), 200
    try:
        data = request.get_json()
        result, status = AuthService.register(data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /register: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /login")
        return jsonify({}), 200
    try:
        data = request.get_json()
        result, status = AuthService.login(data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /login: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/forgot-password', methods=['POST', 'OPTIONS'])
def forgot_password():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /forgot-password")
        return jsonify({}), 200
    try:
        data = request.get_json()
        result, status = AuthService.forgot_password(data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /forgot-password: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/reset-password', methods=['POST', 'OPTIONS'])
def reset_password():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /reset-password")
        return jsonify({}), 200
    try:
        data = request.get_json()
        result, status = AuthService.reset_password(data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /reset-password: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/google/login')
def google_login():
    try:
        redirect_uri = 'http://localhost:5000/api/auth/google/callback'
        current_app.logger.debug(f"Redirecting to Google with URI: {redirect_uri}")
        return oauth.google.authorize_redirect(redirect_uri)
    except Exception as e:
        current_app.logger.error(f"Error in /google/login: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/google/callback')
def google_callback():
    try:
        result = AuthService.google_callback()
        return result
    except Exception as e:
        current_app.logger.error(f"Error in /google/callback: {str(e)}", exc_info=True)
        return redirect('http://localhost:8501/login?error=' + urllib.parse.quote(str(e)))

@auth_bp.route('/companies', methods=['GET'])
def get_companies():
    try:
        result, status = AuthService.get_companies()
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /companies: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/company/<int:company_id>/users', methods=['GET'])
@token_required
def get_company_users(current_user, company_id):
    try:
        result, status = AuthService.get_company_users(current_user, company_id)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id}/users: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/company/companies', methods=['GET', 'POST'])
@token_required
def manage_companies(current_user):
    try:
        if request.method == 'GET':
            result, status = AuthService.get_companies()
            return jsonify(result), status
        elif request.method == 'POST':
            data = request.get_json()
            result, status = AuthService.create_company(current_user, data)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/companies: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/company/<int:company_id>', methods=['PUT', 'DELETE'])
@token_required
def manage_company(current_user, company_id):
    try:
        if request.method == 'PUT':
            data = request.get_json()
            result, status = AuthService.update_company(current_user, company_id, data)
            return jsonify(result), status
        elif request.method == 'DELETE':
            result, status = AuthService.delete_company(current_user, company_id)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500
@auth_bp.route('/update-profile', methods=['POST'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        result, status = AuthService.update_profile(current_user, data)  # Or UserService if placed there
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /update-profile: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500