from langdetect import detect 
from unidecode import unidecode 
from fuzzywuzzy import fuzz 
import re

SALUTATIONS = {
    "fr": ["bonjour", "salut", "cc", "coucou", "bonsoir", "yo", "bjr", "re"],
    "en": ["hello", "hi", "yo", "hey", "good morning", "good evening"],
    "ar": ["salam", "marhba", "ahlan"]
}

THANKS = {
    "fr": ["merci", "thanks", "shukran", "choukran", "allah ybarek"],
    "en": ["thanks", "thank you", "thx"],
    "ar": ["shokran", "merci"]
}

TECH_KEYWORDS = [
    "python", "java", "javascript", "ai", "machine learning", "docker", "react", "node", "sql",
    "fonction", "framework", "comment", "expliquer", "avantage", "architecture", "bdd", "api"
]

def normalize_message(msg):
    msg = msg.lower()
    msg = unidecode(msg)
    msg = re.sub(r"[^\w\s]", "", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg

def analyze_message(message):
    normalized = normalize_message(message)

    try:
        lang = detect(normalized)
    except:
        lang = "en"

    greetings = SALUTATIONS.get(lang, []) + SALUTATIONS.get("en", [])
    thanks = THANKS.get(lang, []) + THANKS.get("en", [])

    has_greeting = any(fuzz.ratio(normalized, word) >= 85 for word in greetings)
    has_thanks = any(fuzz.ratio(normalized, word) >= 85 for word in thanks)
    has_tech = any(keyword in normalized for keyword in TECH_KEYWORDS)
    is_question = "?" in normalized or len(normalized.split()) >= 4

    return {
        "has_greeting": has_greeting,
        "has_thanks": has_thanks,
        "is_technical": has_tech or is_question
    }
