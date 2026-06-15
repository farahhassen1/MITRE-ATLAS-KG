# eval/precision_semantic.py
import json
import numpy as np
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

# ── CONFIG ───────────────────────────────────────────────────────────────────
NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "29703391"

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
TOP_K            = 10

GOLD_SET = {
    "AML.T0015",  # Evade AI Model
    "AML.T0040",  # AI Model Inference API Access
    "AML.T0043",  # Craft Adversarial Data
    "AML.T0051",  # LLM Prompt Injection
    "AML.T0070",  # RAG Poisoning
}

SYSTEM_DESCRIPTION = (
    "A RAG-based customer support chatbot using GPT-4, "
    "a Pinecone vector database, and a public REST API endpoint."
)

# ── HELPERS ──────────────────────────────────────────────────────────────────
def cosine_similarity(a, b):
    a = np.array(a, dtype=np.float32)
    b = np.array(b, dtype=np.float32)
    norm = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / norm) if norm > 1e-9 else 0.0

# ── CONNECT ──────────────────────────────────────────────────────────────────
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
model  = SentenceTransformer(EMBED_MODEL_NAME)

print(f"System: {SYSTEM_DESCRIPTION}")
print(f"Top-k:  {TOP_K}")
print(f"Gold:   {GOLD_SET}")
print()

# ── CHECK EMBEDDINGS EXIST ───────────────────────────────────────────────────
with driver.session() as session:
    result = session.run("""
        MATCH (te)
        WHERE (te:Technique OR te:SubTechnique)
          AND te.embedding IS NOT NULL
        RETURN count(te) AS nb
    """)
    nb = result.single()["nb"]

if nb == 0:
    print("❌ No embeddings found in Neo4j.")
    print("   Run reasoning_engine.py first — it will compute them automatically.")
    driver.close()
    exit(1)

print(f"✅ {nb} technique embeddings found in Neo4j")

# ── SEMANTIC RETRIEVAL ───────────────────────────────────────────────────────
query_embedding = model.encode(SYSTEM_DESCRIPTION).tolist()

with driver.session() as session:
    result = session.run("""
        MATCH (te)
        WHERE (te:Technique OR te:SubTechnique)
          AND te.embedding IS NOT NULL
        RETURN te.id AS id, te.embedding AS embedding
    """)
    all_techniques = result.data()

scores = []
for t in all_techniques:
    emb   = json.loads(t["embedding"])
    score = cosine_similarity(query_embedding, emb)
    scores.append((t["id"], score))

scores.sort(key=lambda x: x[1], reverse=True)
top_ids = [s[0] for s in scores[:TOP_K]]

print(f"\nTop {TOP_K} retrieved techniques:")
for tech_id, score in scores[:TOP_K]:
    in_gold = "✅" if tech_id in GOLD_SET else "  "
    print(f"  {in_gold} {tech_id}  score={score:.3f}")

# ── METRICS ──────────────────────────────────────────────────────────────────
retrieved = set(top_ids)

tp = len(retrieved & GOLD_SET)
fp = len(retrieved - GOLD_SET)
fn = len(GOLD_SET - retrieved)

precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"\n{'─'*40}")
print(f"  TP={tp}  FP={fp}  FN={fn}")
print(f"  Precision:  {precision:.2f}")
print(f"  Recall:     {recall:.2f}")
print(f"  F1:         {f1:.2f}")
print(f"{'─'*40}")

# ── COMPARISON TABLE ─────────────────────────────────────────────────────────
print(f"""
Comparison vs keyword baseline:

  Method    │ Precision │ Recall │ F1
  ──────────┼───────────┼────────┼──────
  Keyword   │   0.12    │  0.80  │ 0.21
  Semantic  │   {precision:.2f}    │  {recall:.2f}  │ {f1:.2f}
  Delta     │  {precision-0.12:+.2f}    │ {recall-0.80:+.2f}  │ {f1-0.21:+.2f}
""")

# ── MISSED GOLD TECHNIQUES ───────────────────────────────────────────────────
missed = GOLD_SET - retrieved
if missed:
    print(f"Missed gold techniques (FN={fn}):")
    for m in missed:
        score = next((s for tid, s in scores if tid == m), None)
        rank  = next((i+1 for i, (tid, s) in enumerate(scores) if tid == m), None)
        print(f"  {m}  rank={rank}  score={score:.3f}")
else:
    print("✅ All gold techniques retrieved (perfect recall)")

driver.close()
print("\n✅ Evaluation complete.")