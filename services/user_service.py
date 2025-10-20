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
from datetime import datetime

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

        stats = {
            "total_users": User.query.count(),
            "total_companies": Company.query.count()
        }
        return {"statistics": stats}, 200

    @staticmethod
    def get_company_users(current_user, company_id):
        if current_user.role not in ['company_admin', 'website_admin'] or \
           (current_user.role == 'company_admin' and current_user.company_id != company_id):
            return {"error": "Accès non autorisé"}, 403

        users = User.query.filter_by(company_id=company_id).all()
        user_data = [{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        } for user in users]
        return {"users": user_data}, 200

    @staticmethod
    def create_company_user(current_user, data):
        if current_user.role not in ['company_admin', 'website_admin'] or \
           (current_user.role == 'company_admin' and current_user.company_id != data.get('company_id')):
            return {"error": "Accès non autorisé"}, 403

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role", "company_user")
        company_id = data.get("company_id")

        if not all([username, email, password, company_id]):
            return {"error": "Tous les champs (username, email, password, company_id) sont requis"}, 400

        if role not in ['company_user', 'company_admin']:
            return {"error": "Rôle invalide pour un utilisateur d'entreprise"}, 400

        if User.query.filter_by(email=email).first():
            return {"error": "Email déjà utilisé"}, 400

        company = Company.query.get(company_id)
        if not company:
            return {"error": "Entreprise non trouvée"}, 404

        password_hash = hash_password(password)
        new_user = User(username=username, email=email, password=password_hash, role=role, company_id=company_id, first_login=True)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "Utilisateur d'entreprise créé avec succès", "user_id": new_user.id}, 201

    @staticmethod
    def update_company_user(current_user, data):
        if current_user.role not in ['company_admin', 'website_admin']:
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        new_role = data.get("role")

        user = User.query.get(user_id)
        if not user:
            return {"error": "Utilisateur non trouvé"}, 404

        if current_user.role == 'company_admin' and user.company_id != current_user.company_id:
            return {"error": "Accès non autorisé à cet utilisateur"}, 403

        if new_role:
            if new_role not in ['company_user', 'company_admin']:
                return {"error": "Rôle invalide"}, 400
            user.role = new_role

        db.session.commit()
        return {"message": "Utilisateur mis à jour avec succès"}, 200

    @staticmethod
    def delete_company_user(current_user, data):
        if current_user.role not in ['company_admin', 'website_admin']:
            return {"error": "Accès non autorisé"}, 403

        user_id = data.get("user_id")
        user = User.query.get(user_id)
        if not user:
            return {"error": "Utilisateur non trouvé"}, 404

        if current_user.role == 'company_admin' and user.company_id != current_user.company_id:
            return {"error": "Accès non autorisé à cet utilisateur"}, 403

        db.session.delete(user)
        db.session.commit()
        return {"message": "Utilisateur supprimé avec succès"}, 200

    @staticmethod
    def upload_document(current_user, files):
        print("DEBUG: Entering upload_document")  # Debug print: Start
        current_app.logger.debug(f"User {current_user.id} attempting upload")

        if current_user.role not in ['company_user', 'company_admin']:
            print("DEBUG: Access denied")  # Debug print
            return {"error": "Accès non autorisé"}, 403

        if 'file' not in files:
            print("DEBUG: No file in request")  # Debug print
            return {"error": "Aucun fichier fourni"}, 400

        file = files['file']
        if file.filename == '':
            print("DEBUG: Empty filename")  # Debug print
            return {"error": "Aucun fichier sélectionné"}, 400

        if not allowed_file(file.filename):
            print(f"DEBUG: Invalid extension for {file.filename}")  # Debug print
            return {"error": f"Seuls les fichiers {', '.join(ALLOWED_EXTENSIONS)} sont autorisés"}, 400

        try:
            print("DEBUG: Reading file size")  # Debug print
            file_data = file.read()
            if len(file_data) > MAX_FILE_SIZE:
                print("DEBUG: File too large")  # Debug print
                return {"error": "Le fichier est trop volumineux (limite : 10 MB)"}, 400
            file.seek(0)  # Reset pointer

            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)  # Note: filepath var (no underscore)
            print(f"DEBUG: Saving file to {filepath}")  # Debug print: File path
            file.save(filepath)

            if not os.path.exists(filepath):
                print("DEBUG: File save failed - path does not exist")  # Debug print
                raise FileNotFoundError(f"File not saved at {filepath}")

            # Extract text based on file type
            print("DEBUG: Extracting text")  # Debug print
            if filename.lower().endswith('.pdf'):
                with open(filepath, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    text = ""
                    for page in pdf_reader.pages:
                        text += page.extract_text() or ""
            elif filename.lower().endswith('.txt'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    text = f.read()
            else:
                print("DEBUG: Unsupported file type")  # Debug print
                raise ValueError("Type de fichier non supporté")

            # Improved chunking: larger chunks for better context, more overlap
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=200)
            chunks = text_splitter.split_text(text)

            # Create LangChain documents with metadata
            documents = []
            for i, chunk in enumerate(chunks):
                documents.append(LangDocument(
                    page_content=chunk,
                    metadata={
                        "document_id": str(uuid4()),
                        "filename": filename,
                        "chunk_id": i,
                        "company_id": current_user.company_id
                    }
                ))

            # Save or update per-company FAISS index
            faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
            if not os.path.exists(faiss_path):
                os.makedirs(faiss_path)

            print(f"DEBUG: Indexing to FAISS at {faiss_path}")  # Debug print: Vector DB
            if os.path.exists(os.path.join(faiss_path, 'index.faiss')):
                vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
                vector_store.add_documents(documents)
            else:
                vector_store = FAISS.from_documents(documents, embeddings)

            vector_store.save_local(faiss_path)

            # Save document metadata in DB
            print("DEBUG: Creating Document model instance")  # Debug print: Before creation
            new_document = Document(
                company_id=current_user.company_id,
                filename=filename,
                file_path=filepath,  # FIXED: Use 'file_path' (with underscore) to match model
                uploaded_by=current_user.id,
                uploaded_at=datetime.utcnow(),
                embedding=None  # Set if you compute embeddings here
            )
            print("DEBUG: Document instance created successfully")  # Debug print: After creation
            db.session.add(new_document)
            db.session.commit()
            print("DEBUG: DB commit successful")  # Debug print: After commit

            return {"message": "Document téléchargé et indexé avec succès"}, 200
        except Exception as e:
            print("DEBUG: Exception in upload:", str(e))  # Debug print: Error
            print(traceback.format_exc())  # Print full traceback for details
            current_app.logger.error(f"Error processing document: {str(e)}", exc_info=True)
            if 'filepath' in os.path:  # Clean up
                os.remove(filepath)
            return {"error": "Erreur lors du traitement du document"}, 500
    @staticmethod
    def get_documents(current_user):
        if current_user.role not in ['company_user', 'company_admin']:
            return {"error": "Accès non autorisé"}, 403

        documents = Document.query.filter_by(company_id=current_user.company_id).all()
        doc_data = [{
            "id": doc.id,
            "filename": doc.filename,
            "uploaded_at": doc.uploaded_at.isoformat(),
            "uploaded_by": doc.uploaded_by
        } for doc in documents]
        return {"documents": doc_data}, 200

    @staticmethod
    def delete_document(current_user, document_id):
        if current_user.role not in ['company_user', 'company_admin']:
            return {"error": "Accès non autorisé"}, 403

        document = Document.query.get(document_id)
        if not document or document.company_id != current_user.company_id:
            return {"error": "Document non trouvé"}, 404

        # Remove from FAISS (recreate index without this doc – simple but inefficient; for production, use doc deletion if supported)
        faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
        if os.path.exists(faiss_path):
            try:
                vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
                # Note: FAISS doesn't support direct deletion by metadata; rebuild index excluding this doc's chunks
                # For simplicity, if many docs, consider using Pinecone or similar with deletion support.
                # Here, we skip deletion from vector store for now – in production, implement rebuild.
            except Exception as e:
                current_app.logger.error(f"Error removing from FAISS: {str(e)}")

        if os.path.exists(document.filepath):
            os.remove(document.filepath)

        db.session.delete(document)
        db.session.commit()
        return {"message": "Document supprimé avec succès"}, 200

    @staticmethod
    def search_documents(current_user, data):
        if current_user.role not in ['company_user', 'company_admin']:
            return {"error": "Accès non autorisé"}, 403

        query = data.get("query")
        if not query:
            return {"error": "Le champ 'query' est requis"}, 400

        faiss_path = os.path.join(FAISS_DB_FOLDER, str(current_user.company_id))
        index_file = os.path.join(faiss_path, 'index.faiss')
        if not os.path.exists(index_file):
            return {"results": []}, 200

        try:
            print("DEBUG: Loading FAISS for search_documents")  # Added debug
            vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
            print("DEBUG: FAISS loaded successfully")  # Added debug
            # FIXED: Use similarity_search_with_score instead of MMR (compatible fallback)
            results = vector_store.similarity_search_with_score(
                query, k=10, filter={"company_id": current_user.company_id}
            )
            print(f"DEBUG: Retrieved {len(results)} results from FAISS")  # Added debug
        except Exception as e:
            print("DEBUG: FAISS search error:", str(e))  # Added debug
            print(traceback.format_exc())
            current_app.logger.error(f"Error loading or searching FAISS: {str(e)}")
            return {"error": "Erreur lors de la recherche dans les documents"}, 500

        if not results:
            return {"results": []}, 200

        # Aggregate by document_id (unchanged)
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
        index_file = os.path.join(faiss_path, 'index.faiss')
        if not os.path.exists(index_file):
            current_app.logger.debug(f"No FAISS index file at {index_file}")
            return []

        try:
            print("DEBUG: Loading FAISS for get_relevant_document_contents")  # Added debug
            vector_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
            print("DEBUG: FAISS loaded successfully")  # Added debug
            # FIXED: Use similarity_search_with_score (fallback, no MMR for now)
            results = vector_store.similarity_search_with_score(
                query, k=10, filter={"company_id": current_user.company_id}
            )
            print(f"DEBUG: Retrieved {len(results)} relevant chunks from FAISS")  # Added debug
        except Exception as e:
            print("DEBUG: FAISS retrieval error:", str(e))  # Added debug
            print(traceback.format_exc())
            current_app.logger.error(f"Error loading or searching FAISS: {str(e)}")
            return []

        if not results:
            return []

        relevant = []
        seen_docs = set()
        for doc, _ in results:
            metadata = doc.metadata
            d_id = metadata['document_id']
            if d_id not in seen_docs:
                seen_docs.add(d_id)
                snippet = doc.page_content[:800] + "..." if len(doc.page_content) > 800 else doc.page_content
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