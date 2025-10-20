# test_faiss.py (copy-paste, run)
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
company_id = 3  # From logs
vs = FAISS.load_local(f'./faiss_db/{company_id}', embeddings, allow_dangerous_deserialization=True)
results = vs.similarity_search_with_score("how is alice", k=5)
print(results)  # Should show chunks from alice_in_wonderland.txt