from flask import Blueprint, request, jsonify
from services.web_scraper import scrape_web

scraping_bp = Blueprint("scraping", __name__)

@scraping_bp.route('/scrape', methods=['POST'])
def scrape():
    data = request.get_json()
    query = data.get("query", "").strip()
    max_results = data.get("max_results", 10)

    if not query:
        return jsonify({"error": "Le champ 'query' est vide ou manquant."}), 400

    try:
        results = scrape_web(query, max_results=max_results)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": f"Erreur lors du scraping : {str(e)}"}), 500
