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
import PyPDF2
from langchain_community.vectorstores import FAISS  # For vector store
from langchain_huggingface import HuggingFaceEmbeddings  # For free embeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document as LangDocument
from uuid import uuid4  # For generating IDs

# Initialize embeddings (free Hugging Face model)
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

ALLOWED_EXTENSIONS = {'pdf', 'txt'}
UPLOAD_FOLDER = 'Uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit
FAISS_DB_FOLDER = './faiss_db'  # Directory for per-company FAISS indexes

# Ensure directories exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(FAISS_DB_FOLDER):
    os.makedirs(FAISS_DB_FOLDER)

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
        new_user = User(username=username, email=email, password=password_hash, role=role, first_login=True)
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
            "company_id": user.company_id,
            "first_login": user.first_login
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
            company_id=company_id,
            first_login=True
        )
        db.session.add(new_user)
        db.session.commit()

        # Send welcome email (unchanged, assuming mail is set up)
        try:
            msg = Message('Bienvenue sur la plateforme', sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[new_user.email])
            msg.body = f"Cher {new_user.username},\n\nVotre compte a été créé en tant que {role} pour l'entreprise ID {company_id}. Veuillez vous connecter et mettre à jour vos détails lors de votre première connexion.\n\nLien de connexion : http://localhost:8501/login"
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Erreur lors de l'envoi de l'email de bienvenue : {str(e)}")

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
            if filename.endswith('.pdf'):
                try:
                    with open(file_path, 'rb') as f:
                        pdf = PyPDF2.PdfReader(f)
                        for page in pdf.pages:
                            extracted_text = page.extract_text()
                            if extracted_text:
                                text += extracted_text + "\n"
                except Exception as e:
                    current_app.logger.warning(f"Failed to process PDF {filename}: {str(e)}. Saving without text.")

            elif filename.endswith('.txt'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        text = f.read()
                except Exception as e:
                    current_app.logger.warning(f"Failed to read TXT {filename}: {str(e)}. Saving without text.")

            # Save metadata to SQL
            document = Document(
                company_id=current_user.company_id,
                filename=filename,
                file_path=file_path,
                uploaded_by=current_user.id
            )
            db.session.add(document)
            db.session.commit()

            # Chunk and add to FAISS (per company)
            warning = None
            if text:
                text_splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=80)
                chunks = text_splitter.split_text(text)
                documents = [LangDocument(page_content=chunk, metadata={"company_id": current_user.company_id, "document_id": document.id, "filename": filename}) for chunk in chunks]
                ids = [str(uuid4()) for _ in documents]  # Unique IDs

                faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
                if os.path.exists(faiss_path):
                    vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
                    vector_store.add_documents(documents=documents, ids=ids)
                else:
                    vector_store = FAISS.from_documents(documents=documents, embedding=embeddings)
                vector_store.save_local(faiss_path)
            else:
                warning = "Impossible d'extraire le texte pour la recherche"

            current_app.logger.info(f"Document uploaded successfully: {filename}, ID: {document.id}")
            return {
                "message": "Document téléchargé avec succès",
                "document_id": document.id,
                "warning": warning
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

        # Delete from FAISS
        faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
        if os.path.exists(faiss_path):
            vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
            # Find IDs to delete (filter by metadata)
            retriever = vector_store.as_retriever(search_kwargs={"filter": {"document_id": document.id}})
            results = retriever.invoke("dummy query")  # Dummy to fetch docs
            ids_to_delete = [doc.metadata.get('id') for doc in results if 'id' in doc.metadata]  # Assuming IDs stored in metadata if needed
            if ids_to_delete:
                vector_store.delete(ids_to_delete)
                vector_store.save_local(faiss_path)

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

        faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
        if not os.path.exists(faiss_path):
            return {"results": []}, 200

        vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
        results = vector_store.similarity_search_with_score(query, k=10, filter={"company_id": current_user.company_id})

        if not results:
            return {"results": []}, 200

        # Aggregate by document_id
        doc_results = {}
        for doc, score in results:
            metadata = doc.metadata
            d_id = metadata['document_id']
            if d_id not in doc_results:
                doc_results[d_id] = {
                    "id": d_id,
                    "filename": metadata['filename'],
                    "similarity": score,
                    "snippets": []
                }
            doc_results[d_id]['snippets'].append(doc.page_content)
            if score < doc_results[d_id]['similarity']:
                doc_results[d_id]['similarity'] = score

        sorted_results = sorted(doc_results.values(), key=lambda x: x["similarity"])
        return {"results": sorted_results}, 200

    @staticmethod
    def get_relevant_document_contents(query, current_user):
        if not current_user.company_id:
            return []

        faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
        if not os.path.exists(faiss_path):
            return []

        vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
        results = vector_store.similarity_search_with_score(query, k=5, filter={"company_id": current_user.company_id})

        if not results:
            return []

        relevant = []
        seen_docs = set()
        for doc, _ in results:
            metadata = doc.metadata
            d_id = metadata['document_id']
            if d_id not in seen_docs:
                seen_docs.add(d_id)
                snippet = doc.page_content[:500] + "..." if len(doc.page_content) > 500 else doc.page_content
                relevant.append({
                    "filename": metadata['filename'],
                    "snippet": snippet
                })

        return relevant

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
            current_user.password = hash_password(new_password)

        current_user.first_login = False
        db.session.commit()

        return {'message': 'Profil mis à jour avec succès'}, 200