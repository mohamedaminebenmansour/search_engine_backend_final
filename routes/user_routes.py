from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models.user_model import User
from models.Company_model import Company
from models.Document_model import Document
from models.history_model import History, Conversation
from utils.auth_utils import token_required, hash_password, verify_password, generate_jwt
import json
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from sentence_transformers import SentenceTransformer, util
import PyPDF2
from flasgger import swag_from

user_bp = Blueprint("user", __name__)

# Initialize sentence-transformers for document search
model = SentenceTransformer('all-MiniLM-L6-v2')

ALLOWED_EXTENSIONS = {'pdf', 'txt'}
UPLOAD_FOLDER = 'Uploads'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@user_bp.route("/register", methods=["POST", "OPTIONS"])
@swag_from({
    'tags': ['User'],
    'summary': 'Register a new user',
    'description': 'Register a new user with optional company association. Users can register without belonging to any company. For company_admin role, company_name is required.',
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
                    'company_name': {
                        'type': 'string',
                        'example': 'MyCompany',
                        'description': 'Optional. Required only for company_admin role to create or associate with a company.'
                    },
                    'role': {
                        'type': 'string',
                        'enum': ['user', 'company_admin', 'website_admin'],
                        'default': 'user',
                        'description': 'Role of the user. Default is "user".'
                    }
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
                    'token': {'type': 'string'},
                    'user_id': {'type': 'integer'},
                    'username': {'type': 'string'},
                    'role': {'type': 'string'},
                    'company_id': {'type': 'integer', 'nullable': True}
                }
            }
        },
        '400': {
            'description': 'Invalid input, email already in use, or company_name required for company_admin role',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '404': {
            'description': 'Company not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def register():
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /register")
        return jsonify({}), 200

    try:
        # Check if request body is empty or invalid
        if not request.data or request.data == b'' or request.data.decode('utf-8').strip() == '':
            return jsonify({"error": "Requête JSON manquante ou vide"}), 400

        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"error": "Requête JSON invalide"}), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        company_name = data.get("company_name")
        role = data.get("role", "user")

        if not all([username, email, password]):
            return jsonify({"error": "Tous les champs (username, email, password) sont requis"}), 400

        if role not in ['user', 'company_admin', 'website_admin']:
            return jsonify({"error": "Rôle invalide"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Cet email est déjà utilisé"}), 400

        if role == 'company_admin' and not company_name:
            return jsonify({"error": "Nom de l’entreprise requis pour le rôle company_admin"}), 400

        password_hash = hash_password(password)
        new_user = User(username=username, email=email, password=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()  # Commit user to generate user.id

        if company_name:
            if role == 'company_admin':
                if Company.query.filter_by(name=company_name).first():
                    db.session.delete(new_user)  # Clean up user if company creation fails
                    db.session.commit()
                    return jsonify({'error': 'Nom de l’entreprise déjà utilisé'}), 400
                new_company = Company(name=company_name, admin_id=new_user.id)
                db.session.add(new_company)
                db.session.commit()
                new_user.company_id = new_company.id
                db.session.commit()  # Update user with company_id
            else:
                company = Company.query.filter_by(name=company_name).first()
                if not company:
                    db.session.delete(new_user)  # Clean up user if company not found
                    db.session.commit()
                    return jsonify({'error': 'Entreprise non trouvée'}), 404
                new_user.company_id = company.id
                db.session.commit()

        token = generate_jwt(new_user.id)
        return jsonify({
            "token": token,
            "user_id": new_user.id,
            "username": new_user.username,
            "role": new_user.role,
            "company_id": new_user.company_id
        }), 201

    except ValueError as ve:
        current_app.logger.error(f"Invalid JSON: {str(ve)}")
        return jsonify({"error": "Requête JSON invalide"}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /register: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500
@user_bp.route("/login", methods=["POST", "OPTIONS"])
@swag_from({
    'tags': ['User'],
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
                    'token': {'type': 'string'},
                    'user_id': {'type': 'integer'},
                    'username': {'type': 'string'},
                    'role': {'type': 'string'},
                    'company_id': {'type': 'integer', 'nullable': True}
                }
            }
        },
        '400': {
            'description': 'Missing JSON request or required fields',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '401': {
            'description': 'Invalid email or password',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def login():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Requête JSON manquante ou invalide"}), 400

        email = data.get("email")
        password = data.get("password")

        if not all([email, password]):
            return jsonify({"error": "Les champs email et password sont requis"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password):
            return jsonify({"error": "Email ou mot de passe incorrect"}), 401

        token = generate_jwt(user.id)
        return jsonify({
            "token": token,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "company_id": user.company_id
        }), 200

    except ValueError as ve:
        current_app.logger.error(f"Invalid JSON: {str(ve)}")
        return jsonify({"error": "Requête JSON invalide"}), 400
    except Exception as e:
        current_app.logger.error(f"Error in /login: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500

@user_bp.route("/admin/users", methods=["GET", "PUT", "DELETE"])
@token_required
@swag_from({
    'tags': ['User'],
    'summary': 'Manage users',
    'description': 'Manage users (list, update, or delete), restricted to website_admin.',
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': False,
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'integer', 'example': 1},
                    'role': {'type': 'string', 'enum': ['user', 'company_admin', 'website_admin']},
                    'company_id': {'type': 'integer', 'example': 1, 'description': 'Optional company ID to associate user with'}
                }
            }
        }
    ],
    'produces': ['application/json'],
    'responses': {
        '200': {
            'description': 'Users listed or updated/deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'users': {
                        'type': 'array',
                        'items': {
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
            }
        },
        '403': {
            'description': 'Unauthorized access',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '404': {
            'description': 'User or company not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def manage_users(current_user):
    if current_user.role != 'website_admin':
        return jsonify({"error": "Accès non autorisé"}), 403

    try:
        if request.method == "GET":
            users = User.query.all()
            user_data = [{
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "company_id": user.company_id
            } for user in users]
            return jsonify({"users": user_data}), 200

        elif request.method == "PUT":
            data = request.get_json()
            user_id = data.get("user_id")
            new_role = data.get("role")
            new_company_id = data.get("company_id")

            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "Utilisateur non trouvé"}), 404

            if new_role:
                if new_role not in ['user', 'company_admin', 'website_admin']:
                    return jsonify({"error": "Rôle invalide"}), 400
                user.role = new_role

            if new_company_id is not None:
                if new_company_id:
                    company = Company.query.get(new_company_id)
                    if not company:
                        return jsonify({"error": "Entreprise non trouvée"}), 404
                    user.company_id = new_company_id
                else:
                    user.company_id = None

            db.session.commit()
            return jsonify({"message": "Utilisateur mis à jour avec succès"}), 200

        elif request.method == "DELETE":
            data = request.get_json()
            user_id = data.get("user_id")
            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "Utilisateur non trouvé"}), 404
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "Utilisateur supprimé avec succès"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /admin/users: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500

@user_bp.route("/admin/statistics", methods=["GET"])
@token_required
@swag_from({
    'tags': ['User'],
    'summary': 'Get platform statistics',
    'description': 'Retrieve statistics about users, companies, and documents, restricted to website_admin.',
    'security': [{'Bearer': []}],
    'produces': ['application/json'],
    'responses': {
        '200': {
            'description': 'Statistics retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'statistics': {
                        'type': 'object',
                        'properties': {
                            'total_users': {'type': 'integer'},
                            'total_companies': {'type': 'integer'},
                            'total_documents': {'type': 'integer'}
                        }
                    }
                }
            }
        },
        '403': {
            'description': 'Unauthorized access',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def get_statistics(current_user):
    if current_user.role != 'website_admin':
        return jsonify({"error": "Accès non autorisé"}), 403

    try:
        user_count = User.query.count()
        company_count = Company.query.count()
        document_count = Document.query.count()
        stats = {
            "total_users": user_count,
            "total_companies": company_count,
            "total_documents": document_count
        }
        return jsonify({"statistics": stats}), 200

    except Exception as e:
        current_app.logger.error(f"Error in /admin/statistics: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500

@user_bp.route("/company/documents", methods=["POST"])
@token_required
@swag_from({
    'tags': ['User'],
    'summary': 'Upload a document',
    'description': 'Upload a PDF or TXT document for a company, restricted to company_admin.',
    'security': [{'Bearer': []}],
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'in': 'formData',
            'name': 'file',
            'type': 'file',
            'required': True,
            'description': 'PDF or TXT file to upload'
        }
    ],
    'produces': ['application/json'],
    'responses': {
        '201': {
            'description': 'Document uploaded successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'document_id': {'type': 'integer'}
                }
            }
        },
        '400': {
            'description': 'No file provided or invalid file type',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '403': {
            'description': 'Unauthorized access',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def upload_document(current_user):
    if current_user.role != 'company_admin':
        return jsonify({"error": "Accès non autorisé"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier fourni"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Aucun fichier sélectionné"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        text = ""
        if filename.endswith('.pdf'):
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                for page in pdf.pages:
                    text += page.extract_text() or ""

        embedding = model.encode(text, convert_to_tensor=False).tolist()

        document = Document(
            company_id=current_user.company_id,
            filename=filename,
            file_path=file_path,
            uploaded_by=current_user.id,
            embedding=embedding
        )
        db.session.add(document)
        db.session.commit()

        return jsonify({"message": "Document téléchargé avec succès", "document_id": document.id}), 201

    return jsonify({"error": "Type de fichier non autorisé"}), 400

@user_bp.route("/company/documents/search", methods=["POST"])
@token_required
@swag_from({
    'tags': ['User'],
    'summary': 'Search company documents',
    'description': 'Search documents within a company using a text query.',
    'security': [{'Bearer': []}],
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
                    'query': {'type': 'string', 'example': 'contract details'}
                },
                'required': ['query']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Search results',
            'schema': {
                'type': 'object',
                'properties': {
                    'results': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'document_id': {'type': 'integer'},
                                'filename': {'type': 'string'},
                                'similarity': {'type': 'number'}
                            }
                        }
                    }
                }
            }
        },
        '400': {
            'description': 'Missing search query',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '403': {
            'description': 'User not associated with a company',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def search_documents(current_user):
    if not current_user.company_id:
        return jsonify({"error": "Utilisateur non associé à une entreprise"}), 403

    data = request.get_json()
    query = data.get("query")
    if not query:
        return jsonify({"error": "Requête de recherche manquante"}), 400

    try:
        query_embedding = model.encode(query, convert_to_tensor=False)
        documents = Document.query.filter_by(company_id=current_user.company_id).all()
        results = []

        for doc in documents:
            if doc.embedding:
                doc_embedding = doc.embedding
                similarity = util.cos_sim(query_embedding, doc_embedding).item()
                if similarity > 0.5:
                    results.append({
                        "document_id": doc.id,
                        "filename": doc.filename,
                        "similarity": similarity
                    })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return jsonify({"results": results}), 200

    except Exception as e:
        current_app.logger.error(f"Error in /company/documents/search: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500

@user_bp.route("/history", methods=["GET", "PUT", "DELETE", "OPTIONS"])
@token_required
@swag_from({
    'tags': ['User'],
    'summary': 'Manage user history',
    'description': 'Retrieve, update, or delete user search history.',
    'security': [{'Bearer': []}],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': False,
            'schema': {
                'type': 'object',
                'properties': {
                    'history_id': {'type': 'integer', 'example': 1},
                    'query': {'type': 'string', 'example': 'updated query'}
                }
            }
        }
    ],
    'produces': ['application/json'],
    'responses': {
        '200': {
            'description': 'History retrieved, updated, or deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'history': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'search_query': {'type': 'string'},
                                'conversation': {
                                    'type': 'object',
                                    'properties': {
                                        'messages': {'type': 'array', 'items': {'type': 'string'}},
                                        'sources': {'type': 'array', 'items': {'type': 'string'}}
                                    }
                                },
                                'timestamp': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            }
        },
        '400': {
            'description': 'Missing JSON request or required fields',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '404': {
            'description': 'History not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def handle_history(current_user):
    if request.method == "OPTIONS":
        current_app.logger.debug("Received OPTIONS request for /history")
        return jsonify({}), 200

    try:
        if request.method == "GET":
            stmt = (
                db.session.query(History)
                .filter_by(user_id=current_user.id)
                .order_by(History.created_at.desc())
            )
            history = db.session.scalars(stmt).all()
            history_data = []
            for h in history:
                conversation = db.session.query(Conversation).filter_by(history_id=h.id).first()
                history_data.append({
                    "id": h.id,
                    "search_query": h.search_query,
                    "conversation": {
                        "messages": json.loads(conversation.messages) if conversation else [],
                        "sources": json.loads(conversation.sources) if conversation and conversation.sources else []
                    },
                    "timestamp": h.created_at.isoformat()
                })
            return jsonify({"history": history_data}), 200

        elif request.method == "PUT":
            data = request.get_json()
            if not data:
                return jsonify({"error": "Requête JSON manquante"}), 400

            history_id = data.get("history_id")
            new_query = data.get("query")
            if not all([history_id, new_query]):
                return jsonify({"error": "Les champs history_id et query sont requis"}), 400

            history = db.session.query(History).filter_by(id=history_id, user_id=current_user.id).first()
            if not history:
                return jsonify({"error": "Historique non trouvé"}), 404

            history.search_query = new_query
            db.session.commit()
            return jsonify({"message": "Historique mis à jour avec succès"}), 200

        elif request.method == "DELETE":
            data = request.get_json()
            if not data:
                return jsonify({"error": "Requête JSON manquante"}), 400

            history_id = data.get("history_id")
            if not history_id:
                return jsonify({"error": "Le champ history_id est requis"}), 400

            history = db.session.query(History).filter_by(id=history_id, user_id=current_user.id).first()
            if not history:
                return jsonify({"error": "Historique non trouvé"}), 404

            db.session.delete(history)
            db.session.commit()
            return jsonify({"message": "Historique supprimé avec succès"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in /history: {str(e)}", exc_info=True)
        return jsonify({"error": f"Une erreur interne est survenue: {str(e)}"}), 500