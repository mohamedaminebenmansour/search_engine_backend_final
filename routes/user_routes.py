from flask import Blueprint, request, jsonify, current_app
from services.user_service import UserService
from utils.auth_utils import token_required

user_bp = Blueprint("user", __name__)

@user_bp.route("/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /register")
        return jsonify({}), 200
    try:
        data = request.get_json(force=True, silent=True)
        result, status = UserService.register(data)
        return jsonify(result), status
    except ValueError as ve:
        current_app.logger.error(f"Invalid JSON: {str(ve)}")
        return jsonify({"error": "Requête JSON invalide"}), 400
    except Exception as e:
        current_app.logger.error(f"Error in /register: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /login")
        return jsonify({}), 200
    try:
        data = request.get_json(force=True)
        result, status = UserService.login(data)
        return jsonify(result), status
    except ValueError as ve:
        current_app.logger.error(f"Invalid JSON: {str(ve)}")
        return jsonify({"error": "Requête JSON invalide"}), 400
    except Exception as e:
        current_app.logger.error(f"Error in /login: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/admin/users", methods=["GET", "PUT", "DELETE"])
@token_required
def manage_users(current_user):
    try:
        if request.method == "GET":
            result, status = UserService.get_all_users(current_user)
            return jsonify(result), status
        elif request.method == "PUT":
            data = request.get_json()
            result, status = UserService.update_user(current_user, data)
            return jsonify(result), status
        elif request.method == "DELETE":
            data = request.get_json()
            result, status = UserService.delete_user(current_user, data)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /admin/users: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/admin/statistics", methods=["GET"])
@token_required
def get_statistics(current_user):
    try:
        result, status = UserService.get_statistics(current_user)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /admin/statistics: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/company/<int:company_id>/users", methods=["GET"])
@token_required
def get_company_users(current_user, company_id):
    try:
        result, status = UserService.get_company_users(current_user, company_id)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id}/users: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/company/users", methods=["POST", "PUT", "DELETE"])
@token_required
def manage_company_users(current_user):
    try:
        if request.method == "POST":
            data = request.get_json()
            result, status = UserService.create_company_user(current_user, data)
            return jsonify(result), status
        elif request.method == "PUT":
            data = request.get_json()
            result, status = UserService.update_company_user(current_user, data)
            return jsonify(result), status
        elif request.method == "DELETE":
            data = request.get_json()
            result, status = UserService.delete_company_user(current_user, data)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/users: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/company/documents", methods=["GET", "POST", "OPTIONS"])
@token_required
def manage_documents(current_user):
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /company/documents")
        return jsonify({}), 200
    try:
        if request.method == "GET":
            result, status = UserService.get_documents(current_user)
            return jsonify(result), status
        elif request.method == "POST":
            result, status = UserService.upload_document(current_user, request.files)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/documents: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/company/documents/<int:document_id>", methods=["DELETE"])
@token_required
def delete_document(current_user, document_id):
    try:
        result, status = UserService.delete_document(current_user, document_id)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/documents/{document_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/company/documents/search", methods=["POST"])
@token_required
def search_documents(current_user):
    try:
        data = request.get_json()
        result, status = UserService.search_documents(current_user, data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/documents/search: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500

@user_bp.route("/history", methods=["GET", "PUT", "DELETE", "OPTIONS"])
@token_required
def handle_history(current_user):
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /history")
        return jsonify({}), 200
    try:
        if request.method == "GET":
            result, status = UserService.get_history(current_user)
            return jsonify(result), status
        elif request.method == "PUT":
            data = request.get_json()
            result, status = UserService.update_history(current_user, data)
            return jsonify(result), status
        elif request.method == "DELETE":
            data = request.get_json()
            result, status = UserService.delete_history(current_user, data)
            return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /history: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur interne est survenue."}), 500