from flask import current_app
from services.search_service import hybrid_search
from utils.message_filter import analyze_message
from extensions import db
from models.history_model import History, Conversation
from models.user_model import User
import re
import json
from datetime import datetime, timedelta

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

        allowed_models = (
            ["llama2", "gemma", "llama3", "mistral"]
            if current_user else
            ["llama3", "mistral"]
        )

        if model not in allowed_models:
            return {"error": f"Modèle non supporté. Choisissez parmi : {', '.join(allowed_models)}"}, 400

        if not query:
            return {"error": "Le champ 'query' est requis"}, 400

        if current_user and user_id:
            if not isinstance(user_id, int) or user_id != current_user.id:
                return {"error": "Le champ 'user_id' doit être un entier et correspondre à l'utilisateur connecté"}, 400

        try:
            analysis = analyze_message(query)
            greeting = analysis.get("greeting")
        except Exception as e:
            current_app.logger.error(f"Message analysis failed: {str(e)}")
            return {"error": "Erreur lors de l'analyse du message."}, 500

        try:
            result = hybrid_search(query=query, user_id=user_id if current_user else None, model=model, domain=domain)
            formatted_answer = ChatService.format_answer_for_readability(result["answer"])
            if greeting:
                formatted_answer = f"{greeting} ! 😊\n\n{formatted_answer}"
            response = {
                "answer": formatted_answer,
                "sources": result.get("sources", []),
                "detected_domain": result.get("detected_domain", domain)
            }
        except Exception as e:
            current_app.logger.error(f"Hybrid search failed: {str(e)}")
            return {"error": "Erreur dans la recherche hybride."}, 500

        if current_user and user_id:
            try:
                latest_history = db.session.query(History).filter_by(user_id=user_id).order_by(History.created_at.desc()).first()
                is_new_chat = (
                    not latest_history or
                    datetime.utcnow() - latest_history.created_at > timedelta(minutes=5) or
                    history_id is None
                )

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
                else:
                    history_to_use = (
                        db.session.query(History).filter_by(id=history_id).first()
                        if history_id
                        else latest_history
                    )
                    if not history_to_use:
                        return {"error": "Historique spécifié introuvable."}, 404

                    conversation = db.session.query(Conversation).filter_by(history_id=history_to_use.id).first()
                    if conversation:
                        existing_messages = json.loads(conversation.messages) if conversation.messages else []
                        existing_sources = json.loads(conversation.sources) if conversation.sources else []
                        existing_messages.extend([new_message, assistant_message])
                        conversation.messages = json.dumps(existing_messages)
                        conversation.sources = json.dumps(list(set(existing_sources + response["sources"])))
                    else:
                        new_conversation = Conversation(
                            history_id=history_to_use.id,
                            messages=json.dumps(updated_messages),
                            sources=json.dumps(response["sources"])
                        )
                        db.session.add(new_conversation)
                    response["history_id"] = history_to_use.id

                db.session.commit()
                current_app.logger.info(f"Conversation saved for history_id {response['history_id']}")
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Failed to save conversation: {str(e)}")
                return {"error": "Erreur lors de la gestion de l'historique ou de la conversation."}, 500

        return response, 200