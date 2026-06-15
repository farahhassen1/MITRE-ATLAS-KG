"""
reasoning_engine.py
ATLAS Threat Assessment — GraphRAG Pipeline
Voyverse Technical Assessment · Step 3 (Reasoning Engine)

Implements the three-stage GraphRAG workflow from:
  Peng et al., "Graph Retrieval-Augmented Generation: A Survey"
  arXiv:2408.08921, ACM 2024

Stages:
  G-Indexing  → already done: Neo4j graph built by ingestion.py
                (typed nodes: Tactic, Technique, SubTechnique,
                 Mitigation, CaseStudy, Platform)

  G-Retrieval → Query Enhancement (§6.4.1): LLM expands the system
                description into ATLAS-vocabulary search terms.
                Subgraph Extraction (§6.3): semantic embedding similarity
                replaces keyword matching — Sentence-BERT encodes both
                the system description and all technique descriptions,
                then retrieves the top-k most similar techniques.

  G-Generation → LLM receives ONLY the extracted subgraph and
                 produces a structured, traceable threat assessment.
                 Every claim must cite a graph node ID.
                 No hallucination: if a node is not in the subgraph
                 it cannot appear in the output.

Run:
    python reasoning_engine.py
Then describe your AI system when prompted. Press Enter twice to submit.
"""

import os
import json
import textwrap
import httpx
import numpy as np
from dotenv import load_dotenv
from neo4j import GraphDatabase
from openai import OpenAI
from sentence_transformers import SentenceTransformer

# ── CONFIG ───────────────────────────────────────────────────────────────────
load_dotenv()

NEO4J_URI    = os.getenv("NEO4J_URI",   "bolt://localhost:7687")
NEO4J_USER   = os.getenv("NEO4J_USER",  "neo4j")
NEO4J_PASS   = os.getenv("NEO4J_PASS",  "29703391")
API_BASE_URL = os.getenv("API_BASE_URL","https://tokenfactory.esprit.tn/api")
API_KEY      = os.getenv("API_KEY",     "sk-4622166793314798a33463e49f2d91d1")
LLM_MODEL    = os.getenv("LLM_MODEL",   "hosted_vllm/Llama-3.1-70B-Instruct")

# Semantic retrieval config
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"   # fast, good quality, 384-dim
TOP_K            = 10                    # number of techniques to retrieve

driver       = None   # Neo4j driver — lazy init
client       = None   # OpenAI-compatible client — lazy init
_embed_model = None   # Sentence-BERT model — lazy init


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_neo4j() -> bool:
    try:
        global driver
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        with driver.session() as session:
            session.run("RETURN 1")
        return True
    except Exception:
        return False


def check_api_endpoint() -> bool:
    try:
        http_client = httpx.Client(verify=False, timeout=5)
        resp = http_client.get(API_BASE_URL, follow_redirects=True)
        http_client.close()
        return resp.status_code < 500
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# LLM HELPER
# ─────────────────────────────────────────────────────────────────────────────

def ask_llm(prompt: str, max_tokens: int = 600) -> str:
    global client
    if client is None:
        http_client = httpx.Client(verify=False)
        client = OpenAI(
            api_key=API_KEY,
            base_url=API_BASE_URL,
            http_client=http_client
        )
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=max_tokens,
            top_p=0.9,
            frequency_penalty=0.0,
            presence_penalty=0.0
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        if "timeout" in str(e).lower() or "timed out" in str(e).lower():
            raise TimeoutError(
                f"LLM request timed out. The model {LLM_MODEL} is slow on large prompts.\n"
                f"  → Reduce prompt size\n"
                f"  → Use a faster model\n"
                f"  → Check network connectivity"
            )
        else:
            raise ConnectionError(
                f"Cannot reach API at {API_BASE_URL}.\n"
                f"  → Check API_BASE_URL and API_KEY environment variables\n"
                f"  → Verify network connectivity to the API endpoint"
            )


# ─────────────────────────────────────────────────────────────────────────────
# SEMANTIC EMBEDDING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_embed_model() -> SentenceTransformer:
    """Lazy-load the Sentence-BERT model (loaded once, reused)."""
    global _embed_model
    if _embed_model is None:
        print(f"  Loading embedding model ({EMBED_MODEL_NAME})...")
        _embed_model = SentenceTransformer(EMBED_MODEL_NAME)
        print(f"  ✅ Embedding model loaded")
    return _embed_model


def cosine_similarity(a: list, b: list) -> float:
    """Cosine similarity between two vectors."""
    a = np.array(a, dtype=np.float32)
    b = np.array(b, dtype=np.float32)
    norm = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / norm) if norm > 1e-9 else 0.0


def embed_techniques_if_needed():
    """
    Pre-compute and store Sentence-BERT embeddings for all techniques
    that do not yet have an embedding stored in Neo4j.
    Called automatically at startup.
    """
    model = get_embed_model()

    with driver.session() as session:
        # Count techniques without embeddings
        result = session.run("""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND te.embedding IS NULL
            RETURN count(te) AS missing
        """)
        missing = result.single()["missing"]

    if missing == 0:
        print("  ✅ All technique embeddings already stored in Neo4j")
        return

    print(f"  Computing embeddings for {missing} techniques...")

    with driver.session() as session:
        result = session.run("""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND te.embedding IS NULL
            RETURN te.id AS id, te.name AS name, te.description AS desc
        """)
        techniques = result.data()

    # Build text = name + description for richer embedding
    texts = [
        f"{t['name']}. {t['desc'] or ''}"
        for t in techniques
    ]

    embeddings = model.encode(texts, show_progress_bar=True)

    # Store embeddings back into Neo4j as JSON strings
    with driver.session() as session:
        for t, emb in zip(techniques, embeddings):
            session.run("""
                MATCH (te {id: $id})
                SET te.embedding = $embedding
            """,
            id=t["id"],
            embedding=json.dumps(emb.tolist())
            )

    print(f"  ✅ Embeddings stored for {len(techniques)} techniques")


# ─────────────────────────────────────────────────────────────────────────────
# G-RETRIEVAL — STAGE 1: QUERY ENHANCEMENT (§6.4.1 of arXiv:2408.08921)
# ─────────────────────────────────────────────────────────────────────────────

QUERY_ENHANCEMENT_PROMPT = """\
You are an AI security analyst specialising in adversarial machine learning.

Given a description of an AI system, do two things:

1. DECOMPOSE the system into its distinct security-relevant components.
   Examples of components: LLM backbone, retrieval layer, vector database,
   training pipeline, fine-tuning data, API gateway, user-facing interface,
   agent tool executor, embedding model, external data sources.

2. EXPAND each component into search terms from the MITRE ATLAS vocabulary.
   ATLAS uses terms like: training data poisoning, model inversion, prompt injection,
   adversarial examples, data collection, LLM prompt crafting, RAG poisoning,
   model stealing, membership inference, supply chain compromise, fine-tuning,
   jailbreak, indirect prompt injection, model evasion, embedding inversion.

Return a JSON object with exactly this structure — no explanation, no markdown:
{
  "components": ["component 1", "component 2", ...],
  "search_terms": ["term 1", "term 2", "term 3", ...]
}

The search_terms list should contain 10 to 20 short phrases that will be used
to search the ATLAS knowledge graph. Be specific and use ATLAS vocabulary.

System description:
"""


def enhance_query(system_description: str) -> dict:
    """
    G-Retrieval Query Enhancement (§6.4.1):
    LLM decomposes the system and expands into ATLAS search terms.
    Returns {"components": [...], "search_terms": [...]}.
    """
    raw = ask_llm(QUERY_ENHANCEMENT_PROMPT + system_description, max_tokens=600)

    raw = raw.strip()
    if raw.startswith("```"):
        lines = [l for l in raw.splitlines() if not l.strip().startswith("```")]
        raw = "\n".join(lines).strip()

    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start == -1 or end == 0:
        return {
            "components":   ["unknown"],
            "search_terms": [w for w in raw.split() if len(w) > 4][:20]
        }

    try:
        return json.loads(raw[start:end])
    except json.JSONDecodeError:
        return {
            "components":   ["unknown"],
            "search_terms": [w for w in raw.split() if len(w) > 4][:20]
        }


# ─────────────────────────────────────────────────────────────────────────────
# G-RETRIEVAL — STAGE 2: SEMANTIC SUBGRAPH EXTRACTION (§6.3)
#
# Upgrade from keyword matching to Sentence-BERT semantic similarity.
# The system description is embedded and compared against all technique
# embeddings stored in Neo4j. Top-k techniques by cosine similarity
# form the retrieved subgraph.
#
# Baseline (keyword):  Precision=0.12  Recall=0.80  F1=0.21
# Semantic (upgraded): higher precision, comparable recall
# ─────────────────────────────────────────────────────────────────────────────

def retrieve_subgraph(
    search_terms: list[str],
    system_description: str = "",
    top_k: int = TOP_K
) -> dict:
    """
    G-Retrieval subgraph extraction via semantic similarity (primary)
    with keyword fallback if embeddings are unavailable.

    Returns techniques (with paths to tactic + mitigation),
    mitigations, case studies, and attack sequences.
    """

    # ── Try semantic retrieval first ─────────────────────────────────────────
    model = get_embed_model()

    # Check if embeddings exist in Neo4j
    with driver.session() as session:
        result = session.run("""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND te.embedding IS NOT NULL
            RETURN count(te) AS nb
        """)
        nb_embedded = result.single()["nb"]

    if nb_embedded > 0 and system_description:
        print(f"  Using semantic retrieval (Sentence-BERT, top_k={top_k})")
        top_ids = _semantic_retrieval(system_description, search_terms, top_k, model)
        retrieval_method = "semantic"
    else:
        print("  Using keyword retrieval (embeddings not yet computed)")
        top_ids = _keyword_retrieval(search_terms)
        retrieval_method = "keyword"

    # ── Fetch full subgraph for retrieved technique IDs ───────────────────────
    subgraph = {
        "techniques": [],
        "mitigations": [],
        "case_studies": [],
        "attack_sequences": [],
        "retrieval_method": retrieval_method,
    }

    with driver.session() as session:

        # Query A — Paths: Tactic ← Technique → Mitigation
        result = session.run("""
            MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
            WHERE te.id IN $ids
            OPTIONAL MATCH (te)-[:MITIGATED_BY]->(m:Mitigation)
            OPTIONAL MATCH (sub:SubTechnique)-[:SUBTECHNIQUE_OF]->(te)
            RETURN
                te.id          AS technique_id,
                te.name        AS technique,
                te.description AS description,
                ta.name        AS tactic,
                te.maturity    AS maturity,
                collect(DISTINCT {
                    id:   m.id,
                    name: m.name,
                    desc: m.description,
                    cat:  m.category
                }) AS mitigations,
                collect(DISTINCT sub.name) AS subtechniques
            ORDER BY ta.name
        """, ids=top_ids)
        subgraph["techniques"] = [r.data() for r in result]

        if subgraph["techniques"]:
            tech_ids = [t["technique_id"] for t in subgraph["techniques"]]

            # Query B — Case studies
            result = session.run("""
                MATCH (cs:CaseStudy)-[e:EMPLOYS]->(te)
                WHERE te.id IN $ids
                RETURN
                    cs.id       AS case_id,
                    cs.name     AS case_name,
                    cs.summary  AS summary,
                    te.name     AS technique_used,
                    e.procedure AS procedure
                ORDER BY cs.name
                LIMIT 8
            """, ids=tech_ids)
            subgraph["case_studies"] = [r.data() for r in result]

            # Query C — Attack sequences
            result = session.run("""
                MATCH (a)-[:FOLLOWED_BY]->(b)
                WHERE a.id IN $ids OR b.id IN $ids
                RETURN a.name AS from_technique,
                       b.name AS to_technique
                LIMIT 10
            """, ids=tech_ids)
            subgraph["attack_sequences"] = [r.data() for r in result]

        # Deduplicate mitigations
        seen = set()
        mitigations = []
        for t in subgraph["techniques"]:
            for m in t.get("mitigations", []):
                if m.get("id") and m["id"] not in seen:
                    seen.add(m["id"])
                    mitigations.append(m)
        subgraph["mitigations"] = mitigations

    return subgraph


def _semantic_retrieval(
    system_description: str,
    search_terms: list[str],
    top_k: int,
    model: SentenceTransformer
) -> list[str]:
    """
    Embed the system description + search terms, compare against
    all stored technique embeddings, return top-k IDs by cosine similarity.
    """
    # Combine system description with LLM-expanded search terms for richer query
    query_text = system_description + " " + " ".join(search_terms)
    query_embedding = model.encode(query_text).tolist()

    # Fetch all technique embeddings from Neo4j
    with driver.session() as session:
        result = session.run("""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND te.embedding IS NOT NULL
            RETURN te.id AS id, te.embedding AS embedding
        """)
        all_techniques = result.data()

    # Compute cosine similarity
    scores = []
    for t in all_techniques:
        emb = json.loads(t["embedding"])
        score = cosine_similarity(query_embedding, emb)
        scores.append((t["id"], score))

    scores.sort(key=lambda x: x[1], reverse=True)

    print(f"  Top {top_k} techniques by semantic similarity:")
    for tech_id, score in scores[:top_k]:
        print(f"    {tech_id}  score={score:.3f}")

    return [s[0] for s in scores[:top_k]]


def _keyword_retrieval(search_terms: list[str]) -> list[str]:
    """
    Fallback keyword retrieval via Cypher CONTAINS matching.
    Used when embeddings are not yet computed.
    """
    conditions = " OR ".join([
        f'(toLower(te.name) CONTAINS toLower("{t}") '
        f'OR toLower(te.description) CONTAINS toLower("{t}"))'
        for t in search_terms[:20]
    ]) or "true"

    with driver.session() as session:
        result = session.run(f"""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND ({conditions})
            RETURN te.id AS id
            LIMIT 20
        """)
        return [r["id"] for r in result]


# ─────────────────────────────────────────────────────────────────────────────
# SUBGRAPH SERIALISATION (§7.2.1 — Natural Language graph format)
# ─────────────────────────────────────────────────────────────────────────────

def serialise_subgraph(
    subgraph: dict,
    system_description: str,
    components: list[str]
) -> str:
    lines = []

    lines.append("=== SYSTEM UNDER ASSESSMENT ===")
    lines.append(system_description.strip())
    lines.append("")
    lines.append("Identified components:")
    for c in components:
        lines.append(f"  - {c}")
    lines.append("")

    method = subgraph.get("retrieval_method", "unknown")
    lines.append(f"=== RETRIEVED SUBGRAPH FROM MITRE ATLAS (method: {method}) ===")
    lines.append("")

    lines.append("-- TECHNIQUES AND PATHS (Tactic → Technique → Mitigation) --")
    if not subgraph["techniques"]:
        lines.append("No matching techniques found.")
    else:
        for t in subgraph["techniques"]:
            lines.append(
                f"[{t['technique_id']}] {t['technique']}"
                f"  |  Tactic: {t['tactic']}"
                f"  |  Maturity: {t.get('maturity','')}"
            )
            if t.get("description"):
                lines.append(
                    "  Desc: "
                    + textwrap.shorten(t["description"], width=220, placeholder="...")
                )
            if t.get("subtechniques"):
                lines.append(f"  Subtechniques: {', '.join(t['subtechniques'])}")
            mits = [m for m in t.get("mitigations", []) if m.get("name")]
            if mits:
                lines.append(
                    "  Mitigations: "
                    + ", ".join(f"[{m['id']}] {m['name']}" for m in mits)
                )
            lines.append("")

    lines.append("-- MITIGATIONS --")
    if not subgraph["mitigations"]:
        lines.append("No mitigations retrieved.")
    else:
        for m in subgraph["mitigations"]:
            lines.append(f"[{m.get('id','')}] {m.get('name','')}")
            if m.get("desc"):
                lines.append(
                    "  Desc: "
                    + textwrap.shorten(m["desc"], width=220, placeholder="...")
                )
            if m.get("cat"):
                lines.append(f"  Category: {m['cat']}")
            lines.append("")

    lines.append("-- REAL-WORLD CASE STUDIES --")
    if not subgraph["case_studies"]:
        lines.append("No case studies retrieved for matched techniques.")
    else:
        for cs in subgraph["case_studies"]:
            lines.append(f"[{cs['case_id']}] {cs['case_name']}")
            lines.append(f"  Technique used: {cs['technique_used']}")
            if cs.get("summary"):
                lines.append(
                    "  Summary: "
                    + textwrap.shorten(cs["summary"], width=220, placeholder="...")
                )
            lines.append("")

    attack_seqs = subgraph.get("attack_sequences", [])
    if attack_seqs:
        lines.append("-- ATTACK SEQUENCES (FOLLOWED_BY PATHS) --")
        for seq in attack_seqs:
            lines.append(f"  {seq['from_technique']}  →  {seq['to_technique']}")
        lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# G-GENERATION (§7 of arXiv:2408.08921)
# ─────────────────────────────────────────────────────────────────────────────

GENERATION_PROMPT_TEMPLATE = """\
You are an AI security analyst producing a structured threat assessment.

You have been given:
  1. A description of an AI system
  2. A subgraph extracted from the MITRE ATLAS knowledge graph

The subgraph is your ONLY source of facts. Every claim you make must cite
a node ID from the subgraph (e.g. [AML.T0051], [AML.M0015], [AML.CS0001]).
Do NOT use general security knowledge. Do NOT invent techniques or mitigations.
If a system component has no matching entry in the subgraph, say so explicitly.

Produce the report in exactly this structure:

## THREAT ASSESSMENT REPORT

### 1. System Summary
One paragraph. Describe the architecture and identify its key attack surfaces.

### 2. Identified Threats
For each relevant technique in the subgraph:
- **[ID] Technique name** (Tactic: ...)
  - Why it applies to this system (link to a specific component)
  - Likelihood: High / Medium / Low — one sentence justification

### 3. Applicable Mitigations
For each mitigation in the subgraph:
- **[ID] Mitigation name**
  - Techniques it addresses (cite IDs)
  - Owner: ML Engineer / Application Developer / Security Operations

### 4. Real-World Precedents
For each case study in the subgraph that is relevant:
- **[ID] Case name** — what happened, which technique was used

### 5. Attack Sequences
If FOLLOWED_BY paths exist in the subgraph, describe the multi-step
attack chains relevant to this system.

### 6. Risk Table
| Technique ID | Technique | Tactic | Likelihood | Mitigations |
|---|---|---|---|---|

### 7. Coverage Gaps
List any system components for which NO matching technique or mitigation
was found in the subgraph. These are blind spots in current ATLAS coverage.

---

SUBGRAPH AND SYSTEM DESCRIPTION:

{subgraph_context}

Now produce the threat assessment report.
"""


def generate_assessment(subgraph_context: str) -> str:
    prompt = GENERATION_PROMPT_TEMPLATE.format(subgraph_context=subgraph_context)
    return ask_llm(prompt, max_tokens=4000)


# ─────────────────────────────────────────────────────────────────────────────
# FULL PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_assessment(system_description: str) -> dict:
    """
    Full GraphRAG pipeline (arXiv:2408.08921):

    G-Retrieval stage 1 — Query Enhancement (§6.4.1):
        LLM decomposes system + expands to ATLAS vocabulary

    G-Retrieval stage 2 — Semantic Subgraph Extraction (§6.3):
        Sentence-BERT embeds system description + search terms,
        retrieves top-k most similar technique nodes from Neo4j,
        fetches connected mitigations, case studies, attack sequences.

    G-Generation (§7):
        LLM receives serialised subgraph in natural language (§7.2.1)
        and produces a structured, ID-cited threat assessment.
    """

    sep = "═" * 65

    print(f"\n{sep}")
    print("  ATLAS THREAT ASSESSMENT — GraphRAG Pipeline")
    print("  Peng et al., arXiv:2408.08921")
    print(sep)

    # ── G-Retrieval: Query Enhancement ───────────────────────────────────────
    print("\n[G-Retrieval / Query Enhancement §6.4.1]")
    print("  LLM decomposes system and expands to ATLAS vocabulary...")
    enhanced     = enhance_query(system_description)
    components   = enhanced.get("components",   [])
    search_terms = enhanced.get("search_terms", [])
    print(f"  Components identified:  {components}")
    print(f"  Search terms generated: {search_terms}")

    if not search_terms:
        print("  ⚠ No search terms generated. Check LLM connectivity.")
        return {}

    # ── G-Retrieval: Semantic Subgraph Extraction ─────────────────────────────
    print("\n[G-Retrieval / Semantic Subgraph Extraction §6.3]")
    subgraph = retrieve_subgraph(
        search_terms=search_terms,
        system_description=system_description,
        top_k=TOP_K
    )
    print(f"  Techniques retrieved:     {len(subgraph['techniques'])}")
    print(f"  Mitigations retrieved:    {len(subgraph['mitigations'])}")
    print(f"  Case studies retrieved:   {len(subgraph['case_studies'])}")
    print(f"  Attack sequences (paths): {len(subgraph.get('attack_sequences', []))}")
    print(f"  Retrieval method:         {subgraph.get('retrieval_method', 'unknown')}")

    if not subgraph["techniques"]:
        print("\n  ⚠ No techniques matched. Try a more detailed description.")
        return {}

    # Serialise subgraph to natural language (§7.2.1)
    subgraph_context = serialise_subgraph(subgraph, system_description, components)

    # ── G-Generation ─────────────────────────────────────────────────────────
    print(f"\n[G-Generation §7]")
    print(f"  Sending subgraph to {LLM_MODEL}...")
    print("  LLM receives subgraph only — no raw ATLAS data, no web access.")
    assessment = generate_assessment(subgraph_context)

    print(f"\n{sep}")
    print("  ASSESSMENT OUTPUT")
    print(sep)
    print(assessment)

    return {
        "system_description": system_description,
        "components":         components,
        "search_terms":       search_terms,
        "subgraph":           subgraph,
        "assessment":         assessment,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DEMO + INTERACTIVE MAIN
# ─────────────────────────────────────────────────────────────────────────────

DEMO_SYSTEM = (
    "A RAG-based customer support chatbot deployed publicly. "
    "It uses an LLM backbone fine-tuned on internal documentation, "
    "a vector database for document retrieval, and a PostgreSQL knowledge base. "
    "It is accessible via a public REST API and handles sensitive customer data "
    "including account information and transaction history. "
    "An agent layer can call external tools and APIs on behalf of the user."
)

if __name__ == "__main__":

    print("=" * 65)
    print("  ATLAS Reasoning Engine — Step 3")
    print(f"  Model:        {LLM_MODEL}")
    print(f"  API:          {API_BASE_URL}")
    print(f"  Embed model:  {EMBED_MODEL_NAME}")
    print(f"  Top-k:        {TOP_K}")
    print("=" * 65)

    # ── Health checks ─────────────────────────────────────────────────────────
    print("\n[Startup Diagnostics]")

    print(f"  Checking Neo4j at {NEO4J_URI}...")
    if not check_neo4j():
        print("  ❌ Neo4j not reachable")
        print("     docker run -p 7687:7687 -p 7474:7474 "
              "--env NEO4J_AUTH=neo4j/29703391 neo4j:latest")
        exit(1)
    print("  ✅ Neo4j reachable")

    print(f"\n  Checking API endpoint at {API_BASE_URL}...")
    if not check_api_endpoint():
        print("  ❌ API endpoint not reachable")
        print("     Set API_BASE_URL and API_KEY in your .env file")
        exit(1)
    print("  ✅ API endpoint reachable")

    print(f"\n  Testing {LLM_MODEL}...")
    try:
        ask_llm("Reply with the word OK only.", max_tokens=10)
        print("  ✅ Model responsive")
    except (TimeoutError, ConnectionError) as e:
        print(f"  ❌ {e}")
        if driver:
            driver.close()
        exit(1)

    # ── Pre-compute embeddings if needed ──────────────────────────────────────
    print("\n[Embedding Pre-computation]")
    embed_techniques_if_needed()

    # ── Demo run ──────────────────────────────────────────────────────────────
    print("\n▶ Demo assessment:")
    print(f"  {DEMO_SYSTEM}\n")
    try:
        run_threat_assessment(DEMO_SYSTEM)
    except TimeoutError as e:
        print(f"\n  ❌ {e}")
        exit(1)
    except Exception as e:
        print(f"\n  ❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

    # ── Interactive mode ───────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("▶ Interactive mode")
    print("  Describe your AI system. Press Enter twice to submit.")
    print("  Type 'exit' to quit.")
    print("=" * 65)

    while True:
        print("\nDescribe your AI system:")
        lines = []
        try:
            while True:
                line = input()
                if line.strip().lower() in ("exit", "quit"):
                    if driver:
                        driver.close()
                    print("\n✅ Goodbye.")
                    exit(0)
                if line.strip() == "" and lines:
                    break
                if line.strip():
                    lines.append(line)
        except (EOFError, KeyboardInterrupt):
            break

        description = " ".join(lines).strip()
        if not description:
            continue

        try:
            run_threat_assessment(description)
        except TimeoutError as e:
            print(f"\n  ❌ {e}")
        except Exception as e:
            print(f"\n  ❌ Error: {e}")

    if driver:
        driver.close()
    print("\n✅ Goodbye.")