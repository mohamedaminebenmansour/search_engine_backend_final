from flask import current_app
from extensions import db, bcrypt, mail
from models.user_model import User
from models.Company_model import Company
import jwt
import datetime
from config import SECRET_KEY
from flask_mail import Message
import secrets
import urllib.parse
from authlib.integrations.flask_client import OAuth
class AuthService:
    
    @staticmethod
    def login(data):
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            return {'error': 'Email ou mot de passe incorrect'}, 401

        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")

        return {
            'message': 'Connexion réussie',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'company_id': user.company_id,
                'first_login': user.first_login  # Added for first-time login detection
            }
        }, 200
    
    @staticmethod
    def update_profile(current_user, data):
        new_username = data.get('username')
        new_email = data.get('email')
        new_password = data.get('password')

        if not any([new_username, new_email, new_password]):
            return {'error': 'Aucune donnée à mettre à jour'}, 400

        if new_username:
            current_user.username = new_username

        if new_email:
            if new_email != current_user.email and User.query.filter_by(email=new_email).first():
                return {'error': 'Email déjà utilisé'}, 400
            current_user.email = new_email

        if new_password:
            current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        current_user.first_login = False
        db.session.commit()

        return {'message': 'Profil mis à jour avec succès'}, 200
    
    @staticmethod
    def register(data):
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')
        company_id = data.get('company_id')
        new_company_name = data.get('new_company_name')

        if not username or not email or not password:
            return {'error': 'Tous les champs (username, email, password) sont requis'}, 400

        if role not in ['user', 'company_user', 'company_admin', 'website_admin']:
            return {'error': 'Rôle invalide'}, 400

        if User.query.filter_by(email=email).first():
            return {'error': 'Email déjà utilisé'}, 400

        if company_id and new_company_name:
            return {'error': 'Ne peut pas spécifier à la fois company_id et new_company_name'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role, first_login=True)

        if new_company_name and role == 'company_admin':
            if Company.query.filter_by(name=new_company_name).first():
                return {'error': 'Nom de l’entreprise déjà utilisé'}, 400
            db.session.add(new_user)
            db.session.flush()
            new_company = Company(name=new_company_name, admin_id=new_user.id)
            db.session.add(new_company)
            db.session.flush()
            new_user.company_id = new_company.id
        elif company_id:
            company = Company.query.get(company_id)
            if not company:
                return {'error': 'Entreprise non trouvée'}, 404
            if role == 'company_admin' and company.admin_id != new_user.id:
                return {'error': 'Cette entreprise a déjà un administrateur'}, 400
            new_user.company_id = company_id
            db.session.add(new_user)
        else:
            db.session.add(new_user)

        db.session.commit()

        return {
            'message': 'Utilisateur enregistré avec succès',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'role': new_user.role,
                'company_id': new_user.company_id
            }
        }, 201

    @staticmethod
    def forgot_password(data):
        email = data.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return {'error': 'Email non trouvé'}, 404

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
            return {'message': 'Email de réinitialisation envoyé'}, 200
        except Exception as e:
            current_app.logger.error(f"Erreur lors de l'envoi de l'email : {str(e)}")
            return {'error': 'Erreur lors de l’envoi de l’email'}, 500

    @staticmethod
    def reset_password(data):
        reset_token = data.get('token')
        new_password = data.get('password')

        if not reset_token or not new_password:
            return {'error': 'Token et nouveau mot de passe requis'}, 400

        user = User.query.filter_by(reset_token=reset_token).first()
        if not user:
            return {'error': 'Token invalide'}, 400

        if user.reset_token_expiry < datetime.datetime.utcnow():
            return {'error': 'Token expiré'}, 400

        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        return {'message': 'Mot de passe réinitialisé avec succès'}, 200

    @staticmethod
    def google_callback():
        token = oauth.google.authorize_access_token()
        if not token:
            return jsonify({'error': 'Échec de l\'authentification Google'}), 401

        userinfo = oauth.google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
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
                role='user',
                first_login=True
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

    @staticmethod
    def get_companies():
        companies = Company.query.all()
        company_data = [{
            'id': company.id,
            'name': company.name,
            'admin_id': company.admin_id,
            'created_at': company.created_at.isoformat()
        } for company in companies]
        return {'companies': company_data}, 200

    @staticmethod
    def get_company_users(current_user, company_id):
        if current_user.role != 'company_admin' and current_user.role != 'website_admin':
            return {'error': 'Accès non autorisé'}, 403
        if current_user.role == 'company_admin' and current_user.company_id != company_id:
            return {'error': 'Vous ne pouvez accéder qu’aux utilisateurs de votre entreprise'}, 403

        company = Company.query.get(company_id)
        if not company:
            return {'error': 'Entreprise non trouvée'}, 404

        users = User.query.filter_by(company_id=company_id).all()
        user_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        } for user in users]
        return {'users': user_data}, 200


    @staticmethod
    def create_company(current_user, data):
        if current_user.role != 'website_admin':
            return {'error': 'Accès non autorisé'}, 403

        name = data.get('name')
        admin_id = data.get('admin_id')

        if not name:
            return {'error': 'Nom de l’entreprise requis'}, 400

        if Company.query.filter_by(name=name).first():
            return {'error': 'Nom de l’entreprise déjà utilisé'}, 400

        new_admin = None
        if not admin_id:
            admin_username = data.get('admin_username')
            admin_email = data.get('admin_email')
            admin_password = data.get('admin_password')

            if not all([admin_username, admin_email, admin_password]):
                return {'error': 'Détails de l’administrateur requis si aucun admin_id n’est fourni'}, 400

            if User.query.filter_by(email=admin_email).first():
                return {'error': 'Email déjà utilisé'}, 400

            hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
            new_admin = User(username=admin_username, email=admin_email, password=hashed_password, role='company_admin', first_login=True)
            db.session.add(new_admin)
            db.session.flush()
            admin_id = new_admin.id
        else:
            admin = User.query.get(admin_id)
            if not admin:
                return {'error': 'Administrateur non trouvé'}, 404
            if admin.role != 'company_admin':
                return {'error': 'L’utilisateur spécifié n’est pas un company_admin'}, 400
            if admin.company_id:
                return {'error': 'Cet administrateur est déjà associé à une autre entreprise'}, 400

        new_company = Company(name=name, admin_id=admin_id)
        db.session.add(new_company)
        db.session.flush()

        if admin_id:
            if new_admin:
                new_admin.company_id = new_company.id
            else:
                admin.company_id = new_company.id
        db.session.commit()

        # Send welcome email if new admin was created
        if new_admin:
            try:
                msg = Message('Bienvenue sur la plateforme', sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[new_admin.email])
                msg.body = f"Cher {new_admin.username},\n\nVotre compte a été créé en tant qu'administrateur de l'entreprise {name}. Veuillez vous connecter et mettre à jour vos détails lors de votre première connexion.\n\nLien de connexion : http://localhost:8501/login"
                mail.send(msg)
            except Exception as e:
                current_app.logger.error(f"Erreur lors de l'envoi de l'email de bienvenue : {str(e)}")

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
    def update_company(current_user, company_id, data):
        if current_user.role != 'website_admin' and (current_user.role != 'company_admin' or current_user.company_id != company_id):
            return {'error': 'Accès non autorisé'}, 403

        company = Company.query.get(company_id)
        if not company:
            return {'error': 'Entreprise non trouvée'}, 404

        name = data.get('name')
        admin_id = data.get('admin_id') if current_user.role == 'website_admin' else None

        if not name:
            return {'error': 'Nom de l’entreprise requis'}, 400

        if Company.query.filter(Company.name == name, Company.id != company_id).first():
            return {'error': 'Nom de l’entreprise déjà utilisé'}, 400

        if admin_id:
            admin = User.query.get(admin_id)
            if not admin:
                return {'error': 'Administrateur non trouvé'}, 404
            if admin.role != 'company_admin':
                return {'error': 'L’utilisateur spécifié n’est pas un company_admin'}, 400
            if admin.company_id and admin.company_id != company_id:
                return {'error': 'Cet administrateur est déjà associé à une autre entreprise'}, 400
            company.admin_id = admin_id
            admin.company_id = company_id

        company.name = name
        db.session.commit()
        return {'message': 'Entreprise mise à jour avec succès'}, 200

    @staticmethod
    def delete_company(current_user, company_id):
        if current_user.role != 'website_admin' and (current_user.role != 'company_admin' or current_user.company_id != company_id):
            return {'error': 'Accès non autorisé'}, 403

        company = Company.query.get(company_id)
        if not company:
            return {'error': 'Entreprise non trouvée'}, 404

        User.query.filter_by(company_id=company_id).update({'company_id': None})
        db.session.delete(company)
        db.session.commit()
        return {'message': 'Entreprise supprimée avec succès'}, 200