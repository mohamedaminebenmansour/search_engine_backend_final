from flask import current_app
from extensions import db
from models.user_model import User
from models.Company_model import Company
from models.Document_model import Document
from models.history_model import History, Conversation
from utils.auth_utils import hash_password, verify_password, generate_jwt
import json
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from sentence_transformers import SentenceTransformer, util
import PyPDF2

# Initialize sentence-transformers for document search
model = SentenceTransformer('all-MiniLM-L6-v2')

ALLOWED_EXTENSIONS = {'pdf', 'txt'}
UPLOAD_FOLDER = 'Uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

# Ensure UPLOAD_FOLDER exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class UserService:
    @staticmethod
    def register(data):
        if not data:
            return {"error": "Requête JSON invalide"}, 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        company_name = data.get("company_name")
        role = data.get("role", "user")

        if not all([username, email, password]):
            return {"error": "Tous les champs (username, email, password) sont requis"}, 400

        if role not in ['user', 'company_admin', 'website_admin']:
            return {"error": "Rôle invalide"}, 400

        if User.query.filter_by(email=email).first():
            return {"error": "Cet email est déjà utilisé"}, 400

        if role == 'company_admin' and not company_name:
            return {"error": "Nom de l’entreprise requis pour le rôle company_admin"}, 400

        password_hash = hash_password(password)
        new_user = User(username=username, email=email, password=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()

        if company_name:
            if role == 'company_admin':
                if Company.query.filter_by(name=company_name).first():
                    db.session.delete(new_user)
                    db.session.commit()
                    return {'error': 'Nom de l’entreprise déjà utilisé'}, 400
                new_company = Company(name=company_name, admin_id=new_user.id)
                db.session.add(new_company)
                db.session.commit()
                new_user.company_id = new_company.id
                db.session.commit()
            else:
                company = Company.query.filter_by(name=company_name).first()
                if not company:
                    db.session.delete(new_user)
                    db.session.commit()
                    return {'error': 'Entreprise non trouvée'}, 404
                new_user.company_id = company.id
                db.session.commit()

        token = generate_jwt(new_user.id)
        return {
            "token": token,
            "user_id": new_user.id,
            "username": new_user.username,
            "role": new_user.role,
            "company_id": new_user.company_id
        }, 201

    @staticmethod
    def login(data):
        if not data:
            return {"error": "Requête JSON manquante ou invalide"}, 400

        email = data.get("email")
        password = data.get("password")

        if not all([email, password]):
            return {"error": "Les champs email et password sont requis"}, 400

        user = User.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password):
            return {"error": "Email ou mot de passe incorrect"}, 401

        token = generate_jwt(user.id)
        return {
            "message": "Connexion réussie",
            "token": token,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "company_id": user.company_id
        }, 200

    @staticmethod
    def get_all_users(current_user):
        if current_user.role != 'website_admin':
            return {"error": "Accès non autorisé"}, 403

        users = User.query.all()
        user_data = [{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "company_id": user.company_id
        } for user in users]
        return {"users": user_data}, 200

    @staticmethod
    def update_user(current_user, data):
        if current_user.role != 'website_admin':
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        new_role = data.get("role")
        new_company_id = data.get("company_id")

        user = User.query.get(user_id)
        if not user:
            return {"error": "Utilisateur non trouvé"}, 404

        if new_role:
            if new_role not in ['user', 'company_admin', 'website_admin']:
                return {"error": "Rôle invalide"}, 400
            user.role = new_role

        if new_company_id is not None:
            if new_company_id:
                company = Company.query.get(new_company_id)
                if not company:
                    return {"error": "Entreprise non trouvée"}, 404
                user.company_id = new_company_id
            else:
                user.company_id = None

        db.session.commit()
        return {"message": "Utilisateur mis à jour avec succès"}, 200

    @staticmethod
    def delete_user(current_user, data):
        if current_user.role != 'website_admin':
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        user = User.query.get(user_id)
        if not user:
            return {"error": "Utilisateur non trouvé"}, 404
        db.session.delete(user)
        db.session.commit()
        return {"message": "Utilisateur supprimé avec succès"}, 200

    @staticmethod
    def get_statistics(current_user):
        if current_user.role != 'website_admin':
            return {"error": "Accès non autorisé"}, 403

        user_count = User.query.count()
        company_count = Company.query.count()
        document_count = Document.query.count()
        stats = {
            "total_users": user_count,
            "total_companies": company_count,
            "total_documents": document_count
        }
        return {"statistics": stats}, 200

    @staticmethod
    def get_company_users(current_user, company_id):
        if current_user.role != 'company_admin' or current_user.company_id != company_id:
            return {"error": "Accès non autorisé"}, 403

        company = Company.query.get(company_id)
        if not company:
            return {"error": "Entreprise non trouvée"}, 404

        users = User.query.filter_by(company_id=company_id).all()
        user_data = [{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "company_id": user.company_id
        } for user in users]
        return {"users": user_data}, 200

    @staticmethod
    def create_company_user(current_user, data):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        email = data.get("email")
        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "company_user")
        company_id = data.get("company_id")

        if not all([email, username, password, company_id]):
            return {"error": "Tous les champs (email, username, password, company_id) sont requis"}, 400

        if role not in ['company_user', 'company_admin']:
            return {"error": "Rôle invalide"}, 400

        if company_id != current_user.company_id:
            return {"error": "Accès non autorisé à cette entreprise"}, 403

        if User.query.filter_by(email=email).first():
            return {"error": "Cet email est déjà utilisé"}, 400

        password_hash = hash_password(password)
        new_user = User(
            username=username,
            email=email,
            password=password_hash,
            role=role,
            company_id=company_id
        )
        db.session.add(new_user)
        db.session.commit()
        return {"message": "Utilisateur créé avec succès", "user_id": new_user.id}, 201

    @staticmethod
    def update_company_user(current_user, data):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        new_role = data.get("role")
        company_id = data.get("company_id")

        if not user_id or not company_id:
            return {"error": "Les champs user_id et company_id sont requis"}, 400

        if company_id != current_user.company_id:
            return {"error": "Accès non autorisé à cette entreprise"}, 403

        user = User.query.get(user_id)
        if not user or user.company_id != company_id:
            return {"error": "Utilisateur non trouvé ou accès non autorisé"}, 404

        if new_role:
            if new_role not in ['company_user', 'company_admin']:
                return {"error": "Rôle invalide"}, 400
            user.role = new_role

        db.session.commit()
        return {"message": "Utilisateur mis à jour avec succès"}, 200

    @staticmethod
    def delete_company_user(current_user, data):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        if not user_id:
            return {"error": "Le champ user_id est requis"}, 400

        user = User.query.get(user_id)
        if not user or user.company_id != current_user.company_id:
            return {"error": "Utilisateur non trouvé ou accès non autorisé"}, 404

        db.session.delete(user)
        db.session.commit()
        return {"message": "Utilisateur supprimé avec succès"}, 200

    @staticmethod
    def get_documents(current_user):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        if not current_user.company_id:
            return {"error": "Utilisateur non associé à une entreprise"}, 403

        documents = Document.query.filter_by(company_id=current_user.company_id).all()
        document_data = [{
            "id": doc.id,
            "filename": doc.filename,
            "file_path": doc.file_path,
            "uploaded_by": doc.uploaded_by,
            "uploaded_at": doc.uploaded_at.isoformat()
        } for doc in documents]
        return {"documents": document_data}, 200

    @staticmethod
    def upload_document(current_user, files):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        if 'file' not in files:
            current_app.logger.error("No file provided in request.files")
            return {"error": "Aucun fichier fourni"}, 400

        file = files['file']
        if file.filename == '':
            current_app.logger.error("No file selected (empty filename)")
            return {"error": "Aucun fichier sélectionné"}, 400

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_FILE_SIZE:
            current_app.logger.error(f"File too large: {file_size} bytes, max allowed: {MAX_FILE_SIZE} bytes")
            return {"error": f"Fichier trop volumineux (max {MAX_FILE_SIZE/1024/1024} MB)"}, 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            current_app.logger.debug(f"Saving file: {filename} to {file_path}")
            file.save(file_path)

            text = ""
            embedding = None
            if filename.endswith('.pdf'):
                try:
                    with open(file_path, 'rb') as f:
                        pdf = PyPDF2.PdfReader(f)
                        for page in pdf.pages:
                            extracted_text = page.extract_text()
                            if extracted_text:
                                text += extracted_text
                    if text:
                        embedding = model.encode(text, convert_to_tensor=False).tolist()
                    else:
                        current_app.logger.warning(f"No text extracted from PDF: {filename}")
                except Exception as e:
                    current_app.logger.warning(f"Failed to process PDF {filename}: {str(e)}. Saving without embedding.")

            elif filename.endswith('.txt'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        text = f.read()
                    embedding = model.encode(text, convert_to_tensor=False).tolist()
                except Exception as e:
                    current_app.logger.warning(f"Failed to read TXT {filename}: {str(e)}. Saving without embedding.")

            document = Document(
                company_id=current_user.company_id,
                filename=filename,
                file_path=file_path,
                uploaded_by=current_user.id,
                embedding=embedding
            )
            db.session.add(document)
            db.session.commit()

            current_app.logger.info(f"Document uploaded successfully: {filename}, ID: {document.id}")
            return {
                "message": "Document téléchargé avec succès",
                "document_id": document.id,
                "warning": "Impossible d'extraire le texte pour la recherche" if not embedding else None
            }, 201

        current_app.logger.error(f"Invalid file type: {file.filename}")
        return {"error": "Type de fichier non autorisé"}, 400

    @staticmethod
    def delete_document(current_user, document_id):
        if current_user.role != 'company_admin':
            return {"error": "Accès non autorisé"}, 403

        document = Document.query.get(document_id)
        if not document or document.company_id != current_user.company_id:
            return {"error": "Document non trouvé ou accès non autorisé"}, 404

        if os.path.exists(document.file_path):
            os.remove(document.file_path)
        db.session.delete(document)
        db.session.commit()
        return {"message": "Document supprimé avec succès"}, 200

    @staticmethod
    def search_documents(current_user, data):
        if not current_user.company_id:
            return {"error": "Utilisateur non associé à une entreprise"}, 403

        query = data.get("query")
        if not query:
            return {"error": "Requête de recherche manquante"}, 400

        query_embedding = model.encode(query, convert_to_tensor=False)
        documents = Document.query.filter_by(company_id=current_user.company_id).all()
        results = []

        for doc in documents:
            if doc.embedding:
                doc_embedding = doc.embedding
                similarity = util.cos_sim(query_embedding, doc_embedding).item()
                if similarity > 0.5:
                    results.append({
                        "id": doc.id,
                        "filename": doc.filename,
                        "similarity": similarity
                    })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return {"results": results}, 200

    @staticmethod
    def get_history(current_user):
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
        return {"history": history_data}, 200

    @staticmethod
    def update_history(current_user, data):
        if not data:
            return {"error": "Requête JSON manquante"}, 400

        history_id = data.get("history_id")
        new_query = data.get("query")
        if not all([history_id, new_query]):
            return {"error": "Les champs history_id et query sont requis"}, 400

        history = db.session.query(History).filter_by(id=history_id, user_id=current_user.id).first()
        if not history:
            return {"error": "Historique non trouvé"}, 404

        history.search_query = new_query
        db.session.commit()
        return {"message": "Historique mis à jour avec succès"}, 200

    @staticmethod
    def delete_history(current_user, data):
        if not data:
            return {"error": "Requête JSON manquante"}, 400

        history_id = data.get("history_id")
        if not history_id:
            return {"error": "Le champ history_id est requis"}, 400

        history = db.session.query(History).filter_by(id=history_id, user_id=current_user.id).first()
        if not history:
            return {"error": "Historique non trouvé"}, 404

        db.session.delete(history)
        db.session.commit()
        return {"message": "Historique supprimé avec succès"}, 200