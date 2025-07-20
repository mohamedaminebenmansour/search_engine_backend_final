from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from extensions import db, bcrypt

from routes.auth_routes import auth_bp, init_auth_routes
from routes.user_routes import user_bp
from routes.scraping_routes import scraping_bp
from routes.chat_routes import chat_bp
from routes.company_routes import company_bp
from flask_migrate import Migrate
from flask_mail import Mail
from flasgger import Swagger

app = Flask(__name__)

# CORS Configuration
CORS(app, resources={
    r"/api/*": {
        "origins": "http://localhost:8501",
        "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True,
        "expose_headers": ["Authorization"]
    }
})

# Handle preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:8501")
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:8501'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response

# Config
app.config['LOG_LEVEL'] = 'DEBUG'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'votre_clef_secrete_super_secure'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mohamedpoly9@gmail.com'
app.config['MAIL_PASSWORD'] = 'qhng eqvq cchg vjcj'
app.config['MAIL_DEFAULT_SENDER'] = 'mohamedpoly9@gmail.com'

# Flasgger Configuration
app.config['SWAGGER'] = {
    'title': 'TrouVai API',
    'uiversion': 3,
    'openapi': '3.0.3',
    'description': 'API for TrouVai document search and management system',
    'version': '1.0.0',
    'termsOfService': '',
    'contact': {
        'email': 'mohamedpoly9@gmail.com'
    },
    'securityDefinitions': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT Authorization header using the Bearer scheme. Example: "Authorization: Bearer {token}"'
        }
    }
}
swagger = Swagger(app)

# Init extensions
db.init_app(app)
bcrypt.init_app(app)
migrate = Migrate(app, db)
init_auth_routes(app)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(user_bp, url_prefix="/api")
app.register_blueprint(scraping_bp, url_prefix="/api")
app.register_blueprint(chat_bp, url_prefix="/api")
app.register_blueprint(company_bp, url_prefix="/api/company")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, host="localhost", port=5000)