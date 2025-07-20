import requests

def generate_answer_with_llm(contexts, query, history=None, model="llama2"):
    """
    Generate a response using a specified LLM model via Ollama.
    
    Args:
        contexts: List of context documents.
        query: User query string.
        history: Conversation history (optional).
        model: Name of the model to use (e.g., 'llama2', 'gemma', 'llama3', 'mistral').
    
    Returns:
        Generated response or error message.
    """
    prompt = (
        "Tu es un assistant intelligent, amical, et très performant. "
        "Tu comprends parfaitement les fautes d'orthographe, de grammaire, les abréviations, et même les questions mal formulées. "
        "Ta mission est de répondre naturellement, comme un humain, en t'adaptant à la situation. "
        "Si la question est simple (comme 'hello'), réponds simplement ('Salut !'), pas avec un long paragraphe. "
        "Si le contexte contient de l'information utile, utilise-le pour améliorer la réponse. "
        "Sinon, fais de ton mieux avec ce que tu comprends.\n\n"
    )

    if history:
        prompt += "Historique de la conversation :\n"
        for turn in history:
            prompt += f"- Utilisateur : {turn['user']}\n"
            prompt += f"- Assistant : {turn['bot']}\n"

    prompt += f"\nQuestion actuelle : {query}\n"

    if contexts:
        prompt += "\nContexte disponible :\n"
        for i, doc in enumerate(contexts[:5], 1):
            prompt += f"[{i}] {doc['text']}\n"

    prompt += "\nRéponds maintenant de façon naturelle et utile :"

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,  # Use the specified model
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()

    except requests.exceptions.RequestException as e:
        print(f"Erreur LLM (Ollama, modèle {model}): {e}")
        return "Je suis désolé, je n’ai pas pu générer de réponse pour le moment."