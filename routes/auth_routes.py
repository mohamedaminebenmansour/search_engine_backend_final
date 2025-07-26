from flask import request, jsonify, Blueprint, current_app, redirect, url_for
from extensions import db, bcrypt
from models.user_model import User
from models.Company_model import Company
import jwt
import datetime
from config import SECRET_KEY
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
import secrets
import urllib.parse
from utils.auth_utils import token_required

auth_bp = Blueprint('auth', __name__)

# Initialize OAuth
oauth = OAuth()

# Initialize Flask-Mail
mail = Mail()

def init_auth_routes(app):
    oauth.init_app(app)
    mail.init_app(app)

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /register")
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    company_id = data.get('company_id')
    new_company_name = data.get('new_company_name')

    if not username or not email or not password:
        return jsonify({'error': 'Tous les champs (username, email, password) sont requis'}), 400

    if role not in ['user', 'company_user', 'company_admin', 'website_admin']:
        return jsonify({'error': 'Rôle invalide'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email déjà utilisé'}), 400

    if company_id and new_company_name:
        return jsonify({'error': 'Ne peut pas spécifier à la fois company_id et new_company_name'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password, role=role)

    if new_company_name and role == 'company_admin':
        if Company.query.filter_by(name=new_company_name).first():
            return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400
        db.session.add(new_user)
        db.session.flush()
        new_company = Company(name=new_company_name, admin_id=new_user.id)
        db.session.add(new_company)
        db.session.flush()
        new_user.company_id = new_company.id
    elif company_id:
        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404
        if role == 'company_admin' and company.admin_id != new_user.id:
            return jsonify({'error': 'Cette entreprise a déjà un administrateur'}), 400
        new_user.company_id = company_id
        db.session.add(new_user)
    else:
        db.session.add(new_user)

    db.session.commit()

    return jsonify({
        'message': 'Utilisateur enregistré avec succès',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'role': new_user.role,
            'company_id': new_user.company_id
        }
    }), 201

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /login")
        return jsonify({}), 200

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    response = {
        'message': 'Connexion réussie',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'company_id': user.company_id
        }
    }
    current_app.logger.debug(f"Login response: {response}")
    return jsonify(response), 200

@auth_bp.route('/forgot-password', methods=['POST', 'OPTIONS'])
def forgot_password():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /forgot-password")
        return jsonify({}), 200

    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email non trouvé'}), 404

    reset_token = secrets.token_urlsafe(32)
    user.reset_token = reset_token
    user.reset_token_expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    db.session.commit()

    try:
        msg = Message(
            subject='Réinitialisation de votre mot de passe',
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        msg.body = f"""
        Pour réinitialiser votre mot de passe, cliquez sur le lien suivant :
        http://localhost:8501/reset-password?token={reset_token}
        Ce lien est valable pendant 1 heure.
        """
        mail.send(msg)
        return jsonify({'message': 'Email de réinitialisation envoyé'}), 200
    except Exception as e:
        current_app.logger.error(f"Erreur lors de l'envoi de l'email : {str(e)}")
        return jsonify({'error': 'Erreur lors de l’envoi de l’email'}), 500

@auth_bp.route('/reset-password', methods=['POST', 'OPTIONS'])
def reset_password():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /reset-password")
        return jsonify({}), 200

    data = request.get_json()
    reset_token = data.get('token')
    new_password = data.get('password')

    if not reset_token or not new_password:
        return jsonify({'error': 'Token et nouveau mot de passe requis'}), 400

    user = User.query.filter_by(reset_token=reset_token).first()
    if not user:
        return jsonify({'error': 'Token invalide'}), 400

    if user.reset_token_expiry < datetime.datetime.utcnow():
        return jsonify({'error': 'Token expiré'}), 400

    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.reset_token = None
    user.reset_token_expiry = None
    db.session.commit()

    return jsonify({'message': 'Mot de passe réinitialisé avec succès'}), 200

@auth_bp.route('/google/login')
def google_login():
    redirect_uri = 'http://localhost:5000/api/auth/google/callback'
    current_app.logger.debug(f"Redirecting to Google with URI: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)

@auth_bp.route('/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        if not token:
            return jsonify({'error': 'Échec de l\'authentification Google'}), 401

        userinfo = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
        if not userinfo or 'email' not in userinfo:
            return jsonify({'error': 'Impossible de récupérer les informations utilisateur'}), 400

        email = userinfo.get('email')
        username = userinfo.get('name', email.split('@')[0])

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                username=username,
                email=email,
                password=bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8'),
                role='user'
            )
            db.session.add(user)
            db.session.commit()

        jwt_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")

        redirect_url = 'http://localhost:8501/google-callback?' + urllib.parse.urlencode({
            'token': jwt_token,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        })
        return redirect(redirect_url)
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la connexion Google : {str(e)}")
        return redirect('http://localhost:8501/login?error=' + urllib.parse.quote(str(e)))

@auth_bp.route('/companies', methods=['GET'])
@token_required
def get_companies(current_user):
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

@auth_bp.route('/company/<int:company_id>/users', methods=['GET'])
@token_required
def get_company_users(current_user, company_id):
    try:
        if current_user.role != 'company_admin' and current_user.role != 'website_admin':
            return jsonify({'error': 'Accès non autorisé'}), 403
        if current_user.role == 'company_admin' and current_user.company_id != company_id:
            return jsonify({'error': 'Vous ne pouvez accéder qu’aux utilisateurs de votre entreprise'}), 403

        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404

        users = User.query.filter_by(company_id=company_id).all()
        user_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        } for user in users]
        return jsonify({'users': user_data}), 200
    except Exception as e:
        current_app.logger.error(f"Error in /company/{company_id}/users: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/company/companies', methods=['GET', 'POST'])
@token_required
def manage_companies(current_user):
    if current_user.role != 'website_admin':
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        if request.method == 'GET':
            companies = Company.query.all()
            company_data = [{
                'id': company.id,
                'name': company.name,
                'admin_id': company.admin_id,
                'created_at': company.created_at.isoformat()
            } for company in companies]
            return jsonify({'companies': company_data}), 200

        elif request.method == 'POST':
            data = request.get_json()
            name = data.get('name')
            admin_id = data.get('admin_id')

            if not name:
                return jsonify({'error': 'Nom de l’entreprise requis'}), 400

            if Company.query.filter_by(name=name).first():
                return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400

            if admin_id:
                admin = User.query.get(admin_id)
                if not admin:
                    return jsonify({'error': 'Administrateur non trouvé'}), 404
                if admin.role != 'company_admin':
                    return jsonify({'error': 'L’utilisateur spécifié n’est pas un company_admin'}), 400
                if admin.company_id and admin.company_id != new_company.id:
                    return jsonify({'error': 'Cet administrateur est déjà associé à une autre entreprise'}), 400

            new_company = Company(name=name, admin_id=admin_id)
            db.session.add(new_company)
            db.session.flush()

            if admin_id:
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
        current_app.logger.error(f"Error in /company/companies: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500

@auth_bp.route('/company/<int:company_id>', methods=['PUT', 'DELETE'])
@token_required
def manage_company(current_user, company_id):
    if current_user.role != 'website_admin' and (current_user.role != 'company_admin' or current_user.company_id != company_id):
        return jsonify({'error': 'Accès non autorisé'}), 403

    try:
        company = Company.query.get(company_id)
        if not company:
            return jsonify({'error': 'Entreprise non trouvée'}), 404

        if request.method == 'PUT':
            data = request.get_json()
            name = data.get('name')
            admin_id = data.get('admin_id') if current_user.role == 'website_admin' else None

            if not name:
                return jsonify({'error': 'Nom de l’entreprise requis'}), 400

            if Company.query.filter(Company.name == name, Company.id != company_id).first():
                return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400

            if admin_id:
                admin = User.query.get(admin_id)
                if not admin:
                    return jsonify({'error': 'Administrateur non trouvé'}), 404
                if admin.role != 'company_admin':
                    return jsonify({'error': 'L’utilisateur spécifié n’est pas un company_admin'}), 400
                if admin.company_id and admin.company_id != company_id:
                    return jsonify({'error': 'Cet administrateur est déjà associé à une autre entreprise'}), 400
                company.admin_id = admin_id
                admin.company_id = company_id

            company.name = name
            db.session.commit()
            return jsonify({'message': 'Entreprise mise à jour avec succès'}), 200

        elif request.method == 'DELETE':
            User.query.filter_by(company_id=company_id).update({'company_id': None})
            db.session.delete(company)
            db.session.commit()
            return jsonify({'message': 'Entreprise supprimée avec succès'}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /company/{company_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500