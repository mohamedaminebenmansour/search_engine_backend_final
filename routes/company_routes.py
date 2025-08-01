from flask import Blueprint, request, jsonify, current_app
from services.company_service import CompanyService
from utils.auth_utils import token_required

company_bp = Blueprint('company', __name__)

@company_bp.route('/company', methods=['POST'])
@token_required
def create_company(current_user):
    try:
        data = request.get_json()
        result, status = CompanyService.create_company(current_user, data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company POST: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['GET'])
@token_required
def get_company(current_user, company_id):
    try:
        result, status = CompanyService.get_company(current_user, company_id)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id} GET: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['PUT'])
@token_required
def update_company(current_user, company_id):
    try:
        data = request.get_json()
        result, status = CompanyService.update_company(current_user, company_id, data)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id} PUT: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['DELETE'])
@token_required
def delete_company(current_user, company_id):
    try:
        result, status = CompanyService.delete_company(current_user, company_id)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id} DELETE: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/companies', methods=['GET'])
@token_required
def get_all_companies(current_user):
    try:
        result, status = CompanyService.get_all_companies(current_user)
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error in /companies: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500