from flask import current_app
from extensions import db
from models.user_model import User
from models.Company_model import Company
from models.Document_model import Document
from datetime import datetime

class CompanyService:
    @staticmethod
    def create_company(current_user, data):
        if current_user.role not in ['company_admin', 'website_admin']:
            return {'error': 'Accès non autorisé'}, 403

        name = data.get('name')
        admin_id = data.get('admin_id')

        if not name:
            return {'error': 'Le nom de l’entreprise est requis'}, 400

        if Company.query.filter_by(name=name).first():
            return {'error': 'Nom de l’entreprise déjà utilisé'}, 400

        if admin_id and current_user.role != 'website_admin':
            return {'error': 'Seul un administrateur du site peut spécifier admin_id'}, 403

        admin = current_user
        if admin_id:
            admin = User.query.get(admin_id)
            if not admin:
                return {'error': 'Administrateur non trouvé'}, 404
            if admin.role != 'company_admin':
                return {'error': 'L’utilisateur spécifié doit être un company_admin'}, 400
            if admin.company_id or admin.company_admin:
                return {'error': 'Cet utilisateur est déjà associé à une entreprise'}, 400

        new_company = Company(name=name, admin_id=admin.id)
        db.session.add(new_company)
        db.session.flush()
        admin.company_id = new_company.id
        db.session.commit()

        return {
            'message': 'Entreprise créée avec succès',
            'company': {
                'id': new_company.id,
                'name': new_company.name,
                'admin_id': new_company.admin_id,
                'created_at': new_company.created_at.isoformat()
            }
        }, 201

    @staticmethod
    def get_company(current_user, company_id):
        company = Company.query.get(company_id)
        if not company:
            return {'error': 'Entreprise non trouvée'}, 404

        if current_user.role != 'website_admin' and current_user.company_id != company_id:
            return {'error': 'Accès non autorisé'}, 403

        return {
            'company': {
                'id': company.id,
                'name': company.name,
                'admin_id': company.admin_id,
                'created_at': company.created_at.isoformat()
            }
        }, 200

    @staticmethod
    def update_company(current_user, company_id, data):
        if current_user.role != 'website_admin' and current_user.company_id != company_id:
            return {'error': 'Accès non autorisé'}, 403

        name = data.get('name')
        admin_id = data.get('admin_id')

        company = Company.query.get(company_id)
        if not company:
            return {'error': 'Entreprise non trouvée'}, 404

        if name:
            if Company.query.filter_by(name=name).first() and name != company.name:
                return {'error': 'Nom de l’entreprise déjà utilisé'}, 400
            company.name = name

        if admin_id and current_user.role == 'website_admin':
            new_admin = User.query.get(admin_id)
            if not new_admin:
                return {'error': 'Nouvel administrateur non trouvé'}, 404
            if new_admin.role != 'company_admin':
                return {'error': 'L’utilisateur spécifié doit être un company_admin'}, 400
            if new_admin.company_id and new_admin.company_id != company_id:
                return {'error': 'Cet utilisateur est déjà associé à une autre entreprise'}, 400
            old_admin = User.query.get(company.admin_id)
            if old_admin:
                old_admin.company_id = None
            company.admin_id = new_admin.id
            new_admin.company_id = company_id

        db.session.commit()
        return {'message': 'Entreprise mise à jour avec succès'}, 200

    @staticmethod
    def delete_company(current_user, company_id):
        current_app.logger.info(f"Starting delete_company service for company_id: {company_id}")
        current_app.logger.info(f"Current user role: {current_user.role}, company_id: {current_user.company_id}")
        
        if current_user.role != 'website_admin' and current_user.company_id != company_id:
            current_app.logger.warning("Access denied in delete_company")
            return {'error': 'Accès non autorisé'}, 403

        company = Company.query.get(company_id)
        if not company:
            current_app.logger.warning(f"Company not found: {company_id}")
            return {'error': 'Entreprise non trouvée'}, 404

        current_app.logger.info(f"Found company: {company.name}, admin_id: {company.admin_id}")
        
        # Break circular dependency by nullifying admin_id
        company.admin_id = None
        db.session.flush()  # Apply the nullification immediately
        
        current_app.logger.info("Admin_id nullified, attempting to delete company")
        db.session.delete(company)
        current_app.logger.info("Company deleted from session, committing...")
        db.session.commit()
        current_app.logger.info("Commit successful")
        return {'message': 'Entreprise supprimée avec succès'}, 200
    @staticmethod
    def get_all_companies(current_user):
        if current_user.role != 'website_admin':
            return {'error': 'Accès non autorisé'}, 403

        companies = Company.query.all()
        company_data = [{
            'id': company.id,
            'name': company.name,
            'admin_id': company.admin_id,
            'created_at': company.created_at.isoformat()
        } for company in companies]
        return {'companies': company_data}, 200