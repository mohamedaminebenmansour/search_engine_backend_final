from services.search_service import hybrid_search

def main():
    query = input("Entrez votre requête : ")
    results = hybrid_search(query)

    print("\nRésultats de recherche :\n")
    for i, res in enumerate(results, 1):
        print(f"{i}. [{res['source'].upper()}] {res['text'][:200]}...")
        print(f"   🔗 Score: {res['score']:.4f}")
        if res.get("url"):
            print(f"   🌐 URL: {res['url']}")
        print()

if __name__ == "__main__":
    main()
