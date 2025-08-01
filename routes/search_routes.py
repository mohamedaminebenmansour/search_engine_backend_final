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
from flasgger import swag_from

auth_bp = Blueprint('auth', __name__)

# Initialize OAuth
oauth = OAuth()
google = oauth.register(
    name='google',
    client_id='892152436615-n3ltnrj2eo6stlo0h03kq39d1k31r9us.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    redirect_uri='http://localhost:5000/api/auth/google/callback',
    client_kwargs={'scope': 'openid email profile'},
)

# Initialize Flask-Mail
mail = Mail()

def init_auth_routes(app):
    oauth.init_app(app)
    mail.init_app(app)

@auth_bp.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Register a new user',
    'description': 'Register a new user with optional company association.',
    'consumes': ['application/json'],
    'produces': ['application/json'],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'john_doe'},
                    'email': {'type': 'string', 'example': 'john@example.com'},
                    'password': {'type': 'string', 'example': 'password123'},
                    'role': {'type': 'string', 'enum': ['user', 'company_admin', 'website_admin'], 'default': 'user'},
                    'company_id': {'type': 'integer', 'example': 1},
                    'new_company_name': {'type': 'string', 'example': 'MyCompany'}
                },
                'required': ['username', 'email', 'password']
            }
        }
    ],
    'responses': {
        '201': {
            'description': 'User registered successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'integer'},
                            'username': {'type': 'string'},
                            'email': {'type': 'string'},
                            'role': {'type': 'string'},
                            'company_id': {'type': 'integer', 'nullable': True}
                        }
                    }
                }
            }
        },
        '400': {'description': 'Invalid input or email already in use'},
        '404': {'description': 'Company not found'}
    }
})
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    company_id = data.get('company_id')
    new_company_name = data.get('new_company_name')

    if not username or not email or not password:
        return jsonify({'error': 'Tous les champs (username, email, password) sont requis'}), 400

    if role not in ['user', 'company_admin', 'website_admin']:
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

@auth_bp.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'User login',
    'description': 'Authenticate a user and return a JWT token.',
    'consumes': ['application/json'],
    'produces': ['application/json'],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'example': 'john@example.com'},
                    'password': {'type': 'string', 'example': 'password123'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'token': {'type': 'string'},
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'integer'},
                            'username': {'type': 'string'},
                            'email': {'type': 'string'},
                            'role': {'type': 'string'},
                            'company_id': {'type': 'integer', 'nullable': True}
                        }
                    }
                }
            }
        },
        '401': {'description': 'Invalid email or password'}
    }
})
def login():
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

    return jsonify({
        'message': 'Connexion réussie',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'company_id': user.company_id
        }
    }), 200

@auth_bp.route('/forgot-password', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Request password reset',
    'description': 'Send a password reset email with a reset token.',
    'consumes': ['application/json'],
    'produces': ['application/json'],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'example': 'john@example.com'}
                },
                'required': ['email']
            }
        }
    ],
    'responses': {
        '200': {'description': 'Password reset email sent'},
        '404': {'description': 'Email not found'},
        '500': {'description': 'Error sending email'}
    }
})
def forgot_password():
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

@auth_bp.route('/reset-password', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Reset user password',
    'description': 'Reset password using a valid reset token.',
    'consumes': ['application/json'],
    'produces': ['application/json'],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'token': {'type': 'string', 'example': 'reset_token'},
                    'password': {'type': 'string', 'example': 'newpassword123'}
                },
                'required': ['token', 'password']
            }
        }
    ],
    'responses': {
        '200': {'description': 'Password reset successfully'},
        '400': {'description': 'Invalid or expired token'}
    }
})
def reset_password():
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
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Initiate Google OAuth login',
    'description': 'Redirects Ascend to Google OAuth login page.',
    'produces': ['application/json'],
    'responses': {
        '302': {'description': 'Redirect to Google OAuth'}
    }
})
def google_login():
    redirect_uri = 'http://localhost:5000/api/auth/google/callback'
    current_app.logger.debug(f"Redirecting to Google with URI: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)

@auth_bp.route('/google/callback')
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Google OAuth callback',
    'description': 'Handle Google OAuth callback and return JWT token.',
    'produces': ['application/json'],
    'responses': {
        '302': {'description': 'Redirect to frontend with JWT token'},
        '401': {'description': 'Google authentication failed'},
        '400': {'description': 'Unable to retrieve user information'}
    }
})
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
@swag_from({
    'tags': ['Authentication'],
    'summary': 'List all companies',
    'description': 'Retrieve a list of all companies.',
    'produces': ['application/json'],
    'responses': {
        '200': {
            'description': 'List of companies',
            'schema': {
                'type': 'object',
                'properties': {
                    'companies': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'name': {'type': 'string'},
                                'admin_id': {'type': 'integer'},
                                'created_at': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            }
        },
        '500': {'description': 'Internal server error'}
    }
})
def get_companies():
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