from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models.user_model import User
from models.Company_model import Company
from utils.auth_utils import token_required
from datetime import datetime

company_bp = Blueprint('company', __name__)

@company_bp.route('/company', methods=['POST'])
@token_required
def create_company(current_user):
    if current_user.role not in ['company_admin', 'website_admin']:
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        data = request.get_json()
        name = data.get('name')
        admin_id = data.get('admin_id')

        if not name:
            return jsonify({'error': 'Le nom de l’entreprise est requis'}), 400

        if Company.query.filter_by(name=name).first():
            return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400

        if admin_id and current_user.role != 'website_admin':
            return jsonify({'error': 'Seul un administrateur du site peut spécifier admin_id'}), 403

        admin = current_user
        if admin_id:
            admin = User.query.get(admin_id)
            if not admin:
                return jsonify({'error': 'Administrateur non trouvé'}), 404
            if admin.role != 'company_admin':
                return jsonify({'error': 'L’utilisateur spécifié doit être un company_admin'}), 400
            if admin.company_id or admin.company_admin:
                return jsonify({'error': 'Cet utilisateur est déjà associé à une entreprise'}), 400

        new_company = Company(name=name, admin_id=admin.id)
        db.session.add(new_company)
        db.session.flush()
        admin.company_id = new_company.id
        db.session.commit()

        return jsonify({
            'message': 'Entreprise créée avec succès',
            'company': {
                'id': new_company.id,
                'name': new_company.name,
                'admin_id': new_company.admin_id,
                'created_at': new_company.created_at.isoformat()
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /company POST: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['GET'])
@token_required
def get_company(current_user, company_id):
    try:
        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404

        if current_user.role != 'website_admin' and current_user.company_id != company_id:
            return jsonify({'error': 'Accès non autorisé'}), 403

        return jsonify({
            'company': {
                'id': company.id,
                'name': company.name,
                'admin_id': company.admin_id,
                'created_at': company.created_at.isoformat()
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id} GET: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['PUT'])
@token_required
def update_company(current_user, company_id):
    if current_user.role != 'website_admin' and current_user.company_admin.id != company_id:
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        data = request.get_json()
        name = data.get('name')
        admin_id = data.get('admin_id')

        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404

        if name:
            if Company.query.filter_by(name=name).first() and name != company.name:
                return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400
            company.name = name

        if admin_id and current_user.role == 'website_admin':
            new_admin = User.query.get(admin_id)
            if not new_admin:
                return jsonify({'error': 'Nouvel administrateur non trouvé'}), 404
            if new_admin.role != 'company_admin':
                return jsonify({'error': 'L’utilisateur spécifié doit être un company_admin'}), 400
            if new_admin.company_id and new_admin.company_id != company_id:
                return jsonify({'error': 'Cet utilisateur est déjà associé à une autre entreprise'}), 400
            old_admin = User.query.get(company.admin_id)
            if old_admin:
                old_admin.company_id = None
            company.admin_id = new_admin.id
            new_admin.company_id = company_id

        db.session.commit()
        return jsonify({'message': 'Entreprise mise à jour avec succès'}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /company/{company_id} PUT: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/company/<int:company_id>', methods=['DELETE'])
@token_required
def delete_company(current_user, company_id):
    if current_user.role != 'website_admin' and current_user.company_admin.id != company_id:
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404

        users = User.query.filter_by(company_id=company_id).all()
        for user in users:
            user.company_id = None

        from models.user_model import Document
        Document.query.filter_by(company_id=company_id).delete()

        db.session.delete(company)
        db.session.commit()
        return jsonify({'message': 'Entreprise supprimée avec succès'}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /company/{company_id} DELETE: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@company_bp.route('/companies', methods=['GET'])
@token_required
def get_all_companies(current_user):
    if current_user.role != 'website_admin':
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        companies = Company.query.all()
        company_data = [{
            'id': company.id,
            'name': company.name,
            'admin_id': company.admin_id,
            'created_at': company.created_at.isoformat()
        } for company in companies]
        return jsonify({'companies': company_data}), 200
    except Exception as e:
        current_app.logger.error(f"Error in /companies: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500