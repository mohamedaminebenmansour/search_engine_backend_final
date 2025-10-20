from flask import current_app
from services.search_service import hybrid_search
from utils.message_filter import analyze_message
from extensions import db
from models.history_model import History, Conversation
from models.user_model import User
from services.user_service import UserService  # Import for document retrieval
import re
import json
from datetime import datetime, timedelta
from langchain_ollama import ChatOllama  # For free local LLM
import os  # Added for file existence checks
import traceback  # Added for error tracing

class ChatService:
    @staticmethod
    def format_answer_for_readability(text):
        text = text.replace("\\n", "\n").replace("\r", "").strip()
        text = re.sub(r"(Je comprends mieux.*?exemples :) *\n*", r"\1\n\n", text, flags=re.IGNORECASE)
        lines = text.splitlines()
        numbered = []
        count = 1
        for line in lines:
            line = line.strip()
            if line.startswith("*"):
                content = line.lstrip("*").strip()
                numbered.append(f"{count}. {content}")
                count += 1
            else:
                numbered.append(line)
        text = "\n".join(numbered)
        text = re.sub(
            r"^Je comprends mieux.*?Voici quelques-uns des exemples :",
            "📊 **Taux de chômage les plus bas dans certains pays :**",
            text,
            flags=re.IGNORECASE
        )
        return text.strip()

    @staticmethod
    def process_chat(data, current_user):
        query = data.get("query", "").strip()
        domain = data.get("domain", "").strip()
        user_id = data.get("user_id")
        messages = data.get("messages", [])
        model = data.get("model", "mistral")
        history_id = data.get("history_id")

        print(f"Processing chat for user: {current_user.username if current_user else 'Anonymous'}, role: {current_user.role if current_user else 'None'}, query: {query}")

        allowed_models = (
            ["llama2", "gemma", "llama3", "mistral"]
            if current_user else
            ["llama3", "mistral"]
        )

        if model not in allowed_models:
            print(f"Invalid model: {model}")
            return {"error": f"Modèle non supporté. Choisissez parmi : {', '.join(allowed_models)}"}, 400

        if not query:
            print("No query provided")
            return {"error": "Le champ 'query' est requis"}, 400

        if current_user and user_id:
            if not isinstance(user_id, int) or user_id != current_user.id:
                print(f"User ID mismatch: provided {user_id}, actual {current_user.id}")
                return {"error": "Le champ 'user_id' doit être un entier et correspondre à l'utilisateur connecté"}, 400

        try:
            analysis = analyze_message(query)
            greeting = analysis.get("greeting")
            print(f"Message analysis: greeting={greeting}")
        except Exception as e:
            current_app.logger.error(f"Message analysis failed: {str(e)}")
            print(f"Message analysis error: {str(e)}")
            return {"error": "Erreur lors de l'analyse du message."}, 500

        formatted_answer = ""
        sources = []
        detected_domain = domain

        if current_user and current_user.role in ['company_user', 'company_admin']:  # Fixed role check
            # Improved RAG for company_user using LangChain, FAISS, Ollama
            print(f"Company user detected, performing improved RAG on company-specific documents for query: {query}")
            relevant_docs = []
            try:
                faiss_path = f"faiss_db/{current_user.company_id}"
                index_file = os.path.join(faiss_path, "index.faiss")
                if not os.path.exists(index_file):
                    raise FileNotFoundError(f"FAISS index file not found at {index_file} – no documents indexed yet for this company.")
                print("DEBUG: Calling get_relevant_document_contents")  # Added debug
                relevant_docs = UserService.get_relevant_document_contents(query, current_user)
                print(f"DEBUG: Got {len(relevant_docs)} relevant docs")  # Added debug
            except Exception as e:
                print("DEBUG: RAG error:", str(e))  # Added debug
                print(traceback.format_exc())
                current_app.logger.error(f"Unexpected error in RAG: {str(e)}")
                # Fall back to no documents without crashing

            if relevant_docs:
                print(f"Found {len(relevant_docs)} relevant document chunks from company-specific vector DB")
                context = "\n\n".join([doc['snippet'] for doc in relevant_docs])
                # Generate response with Ollama (free local LLM) using improved prompt
                llm = ChatOllama(model=model)
                prompt_template = """
                You are a helpful assistant specialized in answering questions based solely on the provided company documents.
                Use only the information from the context below to formulate your answer. Be detailed, accurate, and concise.
                Structure your response clearly: start with a direct answer, then explain step-by-step if needed, and end with any relevant suggestions.
                If the query is not fully answered by the context, state what is known and suggest checking additional documents.
                If no relevant information is in the context, respond with: "Aucun contenu pertinent trouvé dans les documents de votre entreprise."
                
                Context from company documents: {context}
                
                User Query: {query}
                
                Answer:
                """
                prompt = prompt_template.format(context=context, query=query)
                response = llm.invoke(prompt)
                formatted_answer = ChatService.format_answer_for_readability(response.content)
                sources = list(set([doc['filename'] for doc in relevant_docs]))
            else:
                print("No relevant documents found or index missing for this company")
                formatted_answer = "Aucun contenu pertinent trouvé dans les documents de votre entreprise."
        else:
            # Use hybrid_search for other roles (unchanged)
            print("Non-company user, using hybrid search")
            try:
                result = hybrid_search(query=query, user_id=user_id if current_user else None, model=model, domain=domain)
                formatted_answer = ChatService.format_answer_for_readability(result["answer"])
                sources = result.get("sources", [])
                detected_domain = result.get("detected_domain", domain)
                print(f"Hybrid search result: answer length={len(formatted_answer)}, sources={len(sources)}")
            except Exception as e:
                current_app.logger.error(f"Hybrid search failed: {str(e)}")
                print(f"Hybrid search error: {str(e)}")
                return {"error": "Erreur dans la recherche hybride."}, 500

        if greeting:
            formatted_answer = f"{greeting} ! 😊\n\n{formatted_answer}"

        response = {
            "answer": formatted_answer,
            "sources": sources,
            "detected_domain": detected_domain
        }

        # History saving logic (unchanged)
        if current_user and user_id:
            try:
                latest_history = db.session.query(History).filter_by(user_id=user_id).order_by(History.created_at.desc()).first()
                is_new_chat = (
                    not latest_history or
                    datetime.utcnow() - latest_history.created_at > timedelta(minutes=5) or
                    history_id is None
                )
                print(f"History check: is_new_chat={is_new_chat}, latest_history_id={latest_history.id if latest_history else None}")

                new_message = {"content": query, "role": "user", "id": str(datetime.utcnow().timestamp())}
                assistant_message = {"content": formatted_answer, "role": "assistant", "id": str(datetime.utcnow().timestamp() + 0.1)}
                updated_messages = messages + [new_message, assistant_message]

                if is_new_chat:
                    new_history = History(user_id=user_id, search_query=query)
                    db.session.add(new_history)
                    db.session.flush()
                    new_conversation = Conversation(
                        history_id=new_history.id,
                        messages=json.dumps(updated_messages),
                        sources=json.dumps(response["sources"])
                    )
                    db.session.add(new_conversation)
                    response["history_id"] = new_history.id
                    current_app.logger.info(f"New history created with id {new_history.id} for user {user_id}")
                    print(f"New history created: id={new_history.id}")
                else:
                    history_to_use = (
                        db.session.query(History).filter_by(id=history_id).first()
                        if history_id
                        else latest_history
                    )
                    if not history_to_use:
                        print(f"History not found: id={history_id}")
                        return {"error": "Historique spécifié introuvable."}, 404

                    conversation = db.session.query(Conversation).filter_by(history_id=history_to_use.id).first()
                    if conversation:
                        existing_messages = json.loads(conversation.messages) if conversation.messages else []
                        existing_sources = json.loads(conversation.sources) if conversation.sources else []
                        existing_messages.extend([new_message, assistant_message])
                        conversation.messages = json.dumps(existing_messages)
                        conversation.sources = json.dumps(list(set(existing_sources + response["sources"])))
                        print(f"Updated existing conversation for history_id={history_to_use.id}")
                    else:
                        new_conversation = Conversation(
                            history_id=history_to_use.id,
                            messages=json.dumps(updated_messages),
                            sources=json.dumps(response["sources"])
                        )
                        db.session.add(new_conversation)
                        print(f"Created new conversation for history_id={history_to_use.id}")
                    response["history_id"] = history_to_use.id

                db.session.commit()
                current_app.logger.info(f"Conversation saved for history_id {response['history_id']}")
                print(f"Conversation saved: history_id={response['history_id']}")
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Failed to save conversation: {str(e)}")
                print(f"History save error: {str(e)}")
                return {"error": "Erreur lors de la gestion de l'historique ou de la conversation."}, 500

        print("Chat processing complete")
        return response, 200