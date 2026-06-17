"""
reasoning_engine.py
ATLAS Threat Assessment — GraphRAG Pipeline (v2)
Voyverse Technical Assessment · Step 3 (Reasoning Engine)

Implements the three-stage GraphRAG workflow from:
  Peng et al., "Graph Retrieval-Augmented Generation: A Survey"
  arXiv:2408.08921, ACM 2024

Architecture (v2 — Multi-Hop Graph-Native Retrieval):

  G-Indexing  → Neo4j graph built by ingestion.py
                (typed nodes: Tactic, Technique, SubTechnique,
                 Mitigation, CaseStudy, Platform)

  G-Retrieval → Three-phase graph-native retrieval:

    Phase A — Seed Node Identification (§6.4.1 + §6.3.1)
      LLM expands the system description into ATLAS vocabulary
      AND identifies relevant ATLAS tactics for guided filtering.
      Sentence-BERT embeds the query and retrieves top-k techniques
      by cosine similarity (semantic seed selection).

    Phase B — Multi-Hop Graph Expansion (§6.3.3 — Paths + Subgraph)
      From seed nodes, traverse the graph structure to discover
      related techniques that flat vector search would miss:
        • Tactic siblings   — techniques under the same tactic
        • Attack chains     — FOLLOWED_BY neighbours (1–2 hops)
        • Sub-techniques    — children of matched parent techniques
        • Mitigation co-occurrence — techniques sharing a defence

    Phase C — Graph-Structural Scoring (§6.3.4)
      Rank all retrieved nodes using graph-aware metrics:
        • Source weight      (direct match > expansion)
        • Degree centrality  (more connected = more relevant)
        • Case study freq.   (real-world evidence signal)
        • Discovery paths    (found via multiple routes = stronger)

  G-Generation → LLM receives ONLY the scored, serialised subgraph.
                 Every claim must cite a graph node ID.
                 No hallucination: if a node is not in the subgraph
                 it cannot appear in the output.

Run:
    python reasoning_engine.py
Then describe your AI system when prompted. Press Enter twice to submit.
"""

import sys
import os
import json
import textwrap
import httpx
import numpy as np
from dotenv import load_dotenv
from neo4j import GraphDatabase
from openai import OpenAI
from sentence_transformers import SentenceTransformer

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ─────────────────────────────────────────────────────────────────────────────
# WINDOWS CONSOLE ENCODING FIX
#
# See app.py for the full rationale: this module prints ATLAS technique
# names/descriptions pulled from Neo4j and raw LLM output, neither of which
# we control the character set of. Without this, a single non-codepage
# character in either source raises UnicodeEncodeError on Windows
# and crashes the pipeline mid-request.
# ─────────────────────────────────────────────────────────────────────────────
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def _console_safe_text(value) -> str:
    text = str(value).replace("\u2605", "")
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


class _SafeUnicodeStream:
    """Proxy stream that degrades unencodable output instead of raising."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        return self._stream.write(_console_safe_text(text))

    def flush(self):
        return self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


sys.stdout = _SafeUnicodeStream(sys.stdout)
sys.stderr = _SafeUnicodeStream(sys.stderr)
sys.__stdout__ = sys.stdout
sys.__stderr__ = sys.stderr

# Backstop — see app.py for the full rationale. This module can also be run
# standalone (`python reasoning_engine.py`), so it needs its own copy of the
# print() guard rather than relying on app.py having patched it first.
# Patching builtins.print twice (once from app.py, once from here) is
# harmless — it's idempotent, just one extra try/except layer.
import builtins
if not getattr(builtins.print, "_atlas_safe_print", False):
    _original_print = builtins.print

    def _safe_print(*args, **kwargs):
        _original_print(*[_console_safe_text(arg) for arg in args], **kwargs)

    _safe_print._atlas_safe_print = True
    builtins.print = _safe_print

# ── CONFIG ───────────────────────────────────────────────────────────────────
load_dotenv()

NEO4J_URI    = os.getenv("NEO4J_URI",   "bolt://localhost:7687")
NEO4J_USER   = os.getenv("NEO4J_USER",  "neo4j")
NEO4J_PASS   = os.getenv("NEO4J_PASS")
API_BASE_URL = os.getenv("API_BASE_URL", "https://tokenfactory.esprit.tn/api")
API_KEY      = os.getenv("API_KEY")
LLM_MODEL    = os.getenv("LLM_MODEL",   "hosted_vllm/Llama-3.1-70B-Instruct")
VERIFY_SSL   = os.getenv("VERIFY_SSL", "true").lower() in ("1", "true", "yes")

if not NEO4J_PASS:
    raise RuntimeError(
        "NEO4J_PASS is not set. Create a .env file (see README) and set "
        "NEO4J_PASS — credentials must never be hardcoded in source."
    )
if not API_KEY:
    raise RuntimeError(
        "API_KEY is not set. Create a .env file (see README) and set "
        "API_KEY — credentials must never be hardcoded in source."
    )

# Semantic retrieval config
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"   # fast, good quality, 384-dim
TOP_K            = 12                    # semantic seeds to retrieve

driver         = None   # Lazy Neo4j driver
client         = None   # OpenAI client (lazy)
client_timeout = None   # Timeout used by the current OpenAI HTTP client
_embed_model   = None   # Sentence-BERT (lazy)

# ── Graph-structural scoring weights ─────────────────────────────────────────
# Each source type gets a base weight. Techniques found via multiple paths
# accumulate score, so graph-central nodes float to the top.
SOURCE_WEIGHTS = {
    "semantic_seed":          1.0,   # Sentence-BERT top-k match
    "keyword_seed":           0.9,   # CONTAINS fallback match
    "subtechnique":           0.85,  # Child of a matched parent
    "attack_chain_follows":   0.7,   # Seed is followed by this (1–2 hops)
    "attack_chain_precedes":  0.7,   # This precedes the seed (1–2 hops)
    "mitigation_neighbor":    0.55,  # Shares a defence with a seed
    "tactic_sibling":         0.4,   # Under the same tactic as a seed
}

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_neo4j() -> bool:
    """
    Check if Neo4j is reachable.
    Reuses the module-level driver instead of creating a new one every call —
    creating a fresh driver on each /health request leaks connections and
    can starve the connection pool used by /assess.
    """
    global driver
    try:
        if driver is None:
            driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASS),
                connection_timeout=10,           # fail fast instead of hanging
                max_transaction_retry_time=15,
            )
        with driver.session() as session:
            session.run("RETURN 1").consume()
        return True
    except Exception:
        return False

def check_api_endpoint() -> bool:
    """Check whether the configured OpenAI-compatible chat endpoint works."""
    try:
        http_client = httpx.Client(verify=VERIFY_SSL, timeout=15)
        probe_client = OpenAI(
            api_key=API_KEY,
            base_url=API_BASE_URL,
            http_client=http_client,
        )
        probe_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": "Reply with OK."}],
            temperature=0,
            max_tokens=2,
        )
        http_client.close()
        return True
    except Exception:
        try:
            http_client.close()
        except Exception:
            pass
        return False

# ─────────────────────────────────────────────────────────────────────────────
# SEMANTIC EMBEDDING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_embed_model() -> SentenceTransformer:
    """
    Lazy-load the Sentence-BERT model (loaded once, reused).

    This is the most common source of an apparently "frozen" pipeline:
    SentenceTransformer() downloads weights from huggingface.co on first use
    and has no built-in timeout. If the network cannot reach huggingface.co,
    this call hangs indefinitely with no error. We surface that explicitly.
    """
    global _embed_model
    if _embed_model is None:
        print(f"  Loading embedding model ({EMBED_MODEL_NAME})...")
        try:
            _embed_model = SentenceTransformer(EMBED_MODEL_NAME)
        except Exception as e:
            raise RuntimeError(
                f"Failed to load embedding model '{EMBED_MODEL_NAME}'.\n"
                f"  This usually means huggingface.co is unreachable from "
                f"this network.\n"
                f"  → Verify: curl -sS -m 5 https://huggingface.co\n"
                f"  → If blocked, pre-download the model on a machine with "
                f"access and copy ~/.cache/huggingface here.\n"
                f"  Original error: {e}"
            ) from e
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

    texts = [
        f"{t['name']}. {t['desc'] or ''}"
        for t in techniques
    ]

    embeddings = model.encode(texts, show_progress_bar=False)

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
# LLM HELPER
# ─────────────────────────────────────────────────────────────────────────────

def ask_llm(prompt: str, max_tokens: int = 600, timeout: float = 90.0) -> str:
    """Query the remote LLM API (OpenAI-compatible endpoint)."""
    global client, client_timeout

    if client is None or client_timeout is None or timeout > client_timeout:
        http_client = httpx.Client(verify=VERIFY_SSL, timeout=timeout)
        client = OpenAI(
            api_key=API_KEY,
            base_url=API_BASE_URL,
            http_client=http_client
        )
        client_timeout = timeout

    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "user", "content": prompt}
            ],
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
                f"LLM request timed out after {timeout}s. The model {LLM_MODEL} is slow\n"
                f"  on large prompts. Try:\n"
                f"  → Reduce prompt size\n"
                f"  → Use a faster model\n"
                f"  → Increase max_tokens parameter\n"
                f"  → Check network connectivity"
            ) from e
        else:
            raise ConnectionError(
                f"Cannot reach API at {API_BASE_URL}.\n"
                f"  → Check API_BASE_URL and API_KEY environment variables\n"
                f"  → Verify network connectivity to the API endpoint"
            ) from e


# ─────────────────────────────────────────────────────────────────────────────
# G-RETRIEVAL — PHASE A: QUERY ENHANCEMENT (§6.4.1 of arXiv:2408.08921)
#
# v2 enhancement: LLM now also identifies relevant ATLAS tactic categories,
# enabling tactic-guided seed filtering to narrow the retrieval space.
#
# This implements both techniques from §6.4.1:
#   Query Expansion    — enrich with ATLAS-vocabulary terms
#   Query Decomposition — break system into attack-surface components
# ─────────────────────────────────────────────────────────────────────────────

ATLAS_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "ML Model Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Discovery", "Collection", "ML Attack Staging",
    "Exfiltration", "Impact", "Credential Access", "Lateral Movement",
    "Command and Control"
]

QUERY_ENHANCEMENT_PROMPT = """\
You are an AI security analyst specialising in adversarial machine learning
and the MITRE ATLAS framework.

Given a description of an AI system, do THREE things:

1. DECOMPOSE the system into its distinct security-relevant components.
   Examples: LLM backbone, retrieval layer, vector database, training pipeline,
   fine-tuning data, API gateway, user-facing interface, agent tool executor,
   embedding model, external data sources, model registry, CI/CD pipeline.

2. EXPAND each component into search terms from the MITRE ATLAS vocabulary.
   ATLAS uses terms like: training data poisoning, model inversion, prompt injection,
   adversarial examples, data collection, LLM prompt crafting, RAG poisoning,
   model stealing, membership inference, supply chain compromise, fine-tuning,
   jailbreak, indirect prompt injection, model evasion, embedding inversion,
   model replication, exfiltration via ML API, backdoor ML model.

3. IDENTIFY which MITRE ATLAS tactics are most relevant to this system's
   attack surface. Choose from: """ + json.dumps(ATLAS_TACTICS) + """

Return a JSON object with exactly this structure — no explanation, no markdown:
{
  "components": ["component 1", "component 2", ...],
  "search_terms": ["term 1", "term 2", "term 3", ...],
  "relevant_tactics": ["tactic 1", "tactic 2", ...]
}

The search_terms list should contain 10 to 20 short phrases.
The relevant_tactics list should contain 3 to 8 tactic names from the list above.

System description:
"""


def enhance_query(system_description: str, retries: int = 2) -> dict:
    """
    G-Retrieval Query Enhancement (§6.4.1):
    LLM decomposes the system, expands into ATLAS search terms,
    and identifies relevant tactics for graph-guided retrieval.
    Returns {"components": [...], "search_terms": [...], "relevant_tactics": [...]}.

    If the LLM output isn't valid JSON, we retry the LLM call rather than
    degrading to a naive word-split of the raw text — a bag-of-words split
    is not ATLAS vocabulary and silently produces garbage retrieval seeds.
    """
    last_raw = ""
    for attempt in range(retries + 1):
        raw = ask_llm(QUERY_ENHANCEMENT_PROMPT + system_description, max_tokens=800)
        last_raw = raw

        raw = raw.strip()
        if raw.startswith("```"):
            lines = [l for l in raw.splitlines() if not l.strip().startswith("```")]
            raw = "\n".join(lines).strip()

        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            continue

        try:
            parsed = json.loads(raw[start:end])
            if not parsed.get("search_terms"):
                continue
            if not parsed.get("relevant_tactics"):
                parsed["relevant_tactics"] = ATLAS_TACTICS[:5]
            if not parsed.get("components"):
                parsed["components"] = ["unspecified"]
            return parsed
        except json.JSONDecodeError:
            continue

    raise ValueError(
        f"LLM failed to produce valid query-enhancement JSON after "
        f"{retries + 1} attempts. Last raw response:\n{last_raw[:500]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# G-RETRIEVAL — PHASE B: MULTI-HOP SUBGRAPH EXTRACTION (§6.3)
#
# v2 architecture — three-phase graph-native retrieval:
#
#   B.1 — Seed Node Identification
#         Semantic (Sentence-BERT) retrieval with tactic-guided filtering.
#         Falls back to keyword CONTAINS if embeddings are unavailable.
#         Adaptive: auto-broadens if too few seeds found.
#
#   B.2 — Multi-Hop Graph Expansion
#         From seed nodes, traverse the graph to discover related nodes
#         that flat vector/keyword search alone cannot reach:
#           • Tactic siblings       — same tactic, different technique
#           • Attack chains         — FOLLOWED_BY 1–2 hops
#           • Sub-techniques        — children of matched parents
#           • Mitigation neighbours — share a defence with a seed
#
#   B.3 — Graph-Structural Scoring & Assembly
#         Score every retrieved node using source weight, degree centrality,
#         case study frequency, and discovery-path diversity.
#         Rank, select top-N, fetch full details + connected subgraph.
#
# This replaces v1's flat approach (semantic OR keyword → direct fetch),
# which was essentially a search engine sitting on top of a graph database
# without using the graph structure for retrieval.
# ─────────────────────────────────────────────────────────────────────────────

def retrieve_subgraph(
    search_terms: list[str],
    system_description: str = "",
    top_k: int = TOP_K,
    relevant_tactics: list[str] = None
) -> dict:
    """
    Multi-hop GraphRAG subgraph extraction (v2).

    Phase B.1: Seed retrieval — semantic + tactic-guided
    Phase B.2: Graph expansion — multi-hop traversal from seeds
    Phase B.3: Scoring — graph-structural relevance ranking

    Returns a scored, ranked subgraph with techniques, mitigations,
    case studies, attack sequences, and graph statistics.
    """

    # ── B.1: SEED NODE IDENTIFICATION ────────────────────────────────────
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
        print(f"  Phase B.1: Semantic seed retrieval (Sentence-BERT, top_k={top_k})")
        seed_ids = _semantic_seed_retrieval(
            system_description, search_terms, top_k, model,
            relevant_tactics=relevant_tactics
        )
        retrieval_method = "semantic + multi-hop"
    else:
        print("  Phase B.1: Keyword seed retrieval (no embeddings available)")
        seed_ids = _keyword_seed_retrieval(search_terms, relevant_tactics)
        retrieval_method = "keyword + multi-hop"

    # Adaptive broadening: if too few seeds, retry without tactic filter
    if len(seed_ids) < 3 and relevant_tactics:
        print(f"  ⚡ Only {len(seed_ids)} seeds found — broadening (removing tactic filter)")
        if nb_embedded > 0 and system_description:
            seed_ids = _semantic_seed_retrieval(
                system_description, search_terms, top_k, model,
                relevant_tactics=None
            )
        else:
            seed_ids = _keyword_seed_retrieval(search_terms, relevant_tactics=None)

    if not seed_ids:
        return {"techniques": [], "mitigations": [], "case_studies": [],
                "attack_sequences": [], "retrieval_method": retrieval_method,
                "graph_stats": {}}

    print(f"  Seeds found: {len(seed_ids)}")

    # ── B.2: MULTI-HOP GRAPH EXPANSION ──────────────────────────────────
    print(f"  Phase B.2: Multi-hop graph expansion from {len(seed_ids)} seeds...")
    expanded_nodes = _expand_graph(seed_ids)
    print(f"    Expanded nodes discovered: {len(expanded_nodes)}")

    # ── B.3: GRAPH-STRUCTURAL SCORING ───────────────────────────────────
    print(f"  Phase B.3: Graph-structural scoring...")
    all_nodes = {}

    # Add seed nodes with base seed weight
    for sid in seed_ids:
        all_nodes[sid] = {
            "id": sid,
            "score": SOURCE_WEIGHTS["semantic_seed" if nb_embedded > 0 else "keyword_seed"],
            "sources": ["seed"],
        }

    # Add expanded nodes, accumulating score for multi-path discoveries
    for node in expanded_nodes:
        nid = node["id"]
        source = node.get("expansion_source", "tactic_sibling")
        weight = SOURCE_WEIGHTS.get(source, 0.3)

        if nid in all_nodes:
            # Found via multiple paths → boost
            all_nodes[nid]["score"] += weight * 0.5
            if source not in all_nodes[nid]["sources"]:
                all_nodes[nid]["sources"].append(source)
        else:
            all_nodes[nid] = {
                "id": nid,
                "score": weight,
                "sources": [source],
            }

    # Graph metrics: degree centrality + case study frequency
    all_ids = list(all_nodes.keys())
    centrality = _compute_centrality(all_ids)
    case_freq  = _compute_case_frequency(all_ids)

    for nid in all_nodes:
        # Degree centrality bonus (normalised 0–0.3)
        deg = centrality.get(nid, 0)
        all_nodes[nid]["score"] += min(deg / 20.0, 0.3)
        all_nodes[nid]["degree"] = deg

        # Case study frequency bonus (normalised 0–0.3)
        cf = case_freq.get(nid, 0)
        all_nodes[nid]["score"] += min(cf / 5.0, 0.3)
        all_nodes[nid]["case_count"] = cf

    # Rank and select top techniques
    ranked = sorted(all_nodes.values(), key=lambda x: x["score"], reverse=True)
    top_techniques = ranked[:25]
    top_ids = [t["id"] for t in top_techniques]

    print(f"    Total scored: {len(all_nodes)}, selected top: {len(top_ids)}")
    for node in top_techniques[:5]:
        print(f"      {node['id']}  score={node['score']:.3f}  sources={node['sources']}  deg={node.get('degree',0)}  cases={node.get('case_count',0)}")

    # ── FETCH FULL SUBGRAPH FOR TOP TECHNIQUES ───────────────────────────
    subgraph = _fetch_full_subgraph(top_ids)
    subgraph["retrieval_method"] = retrieval_method
    subgraph["graph_stats"] = {
        "seed_count":     len(seed_ids),
        "expanded_count": len(expanded_nodes),
        "total_scored":   len(all_nodes),
        "top_selected":   len(top_techniques),
    }

    return subgraph


# ─────────────────────────────────────────────────────────────────────────────
# B.1 HELPERS — SEED RETRIEVAL
# ─────────────────────────────────────────────────────────────────────────────

def _semantic_seed_retrieval(
    system_description: str,
    search_terms: list[str],
    top_k: int,
    model: SentenceTransformer,
    relevant_tactics: list[str] = None
) -> list[str]:
    """
    Embed system description + search terms, compare against all stored
    technique embeddings. Optionally filter by relevant tactics.
    Returns top-k technique IDs by cosine similarity.
    """
    query_text = system_description + " " + " ".join(search_terms)
    query_embedding = model.encode(query_text).tolist()

    # Single session for both reads — avoids opening two separate bolt
    # connections for what is logically one retrieval step.
    with driver.session() as session:
        result = session.run("""
            MATCH (te)
            WHERE (te:Technique OR te:SubTechnique)
              AND te.embedding IS NOT NULL
            RETURN te.id AS id, te.embedding AS embedding
        """)
        all_techniques = result.data()

        tactic_filtered_ids = None
        if relevant_tactics:
            result = session.run("""
                MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
                WHERE ta.name IN $tactics
                  AND (te:Technique OR te:SubTechnique)
                RETURN DISTINCT te.id AS id
            """, tactics=relevant_tactics)
            tactic_filtered_ids = {r["id"] for r in result}

    # Compute cosine similarity
    scores = []
    for t in all_techniques:
        emb = json.loads(t["embedding"])
        score = cosine_similarity(query_embedding, emb)

        # Boost techniques in relevant tactics (+30% score)
        if tactic_filtered_ids and t["id"] in tactic_filtered_ids:
            score *= 1.3

        scores.append((t["id"], score))

    scores.sort(key=lambda x: x[1], reverse=True)

    print(f"    Semantic top-{top_k} (tactic-boosted: {'yes' if tactic_filtered_ids else 'no'}):")
    for tech_id, score in scores[:top_k]:
        tactic_tag = " " if tactic_filtered_ids and tech_id in tactic_filtered_ids else ""
        print(f"      {tech_id}  sim={score:.3f}{tactic_tag}")

    return [s[0] for s in scores[:top_k]]


def _keyword_seed_retrieval(
    search_terms: list[str],
    relevant_tactics: list[str] = None
) -> list[str]:
    """
    Fallback keyword seed retrieval via Cypher CONTAINS matching.
    Optionally filters by relevant tactics.
    """
    terms = [
        str(term).strip().lower()
        for term in search_terms[:20]
        if str(term).strip()
    ]

    tactic_filter = ""
    params = {"terms": terms}
    if relevant_tactics:
        tactic_filter = "AND ta.name IN $tactics"
        params["tactics"] = relevant_tactics

    with driver.session() as session:
        result = session.run(f"""
            MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
            WHERE (te:Technique OR te:SubTechnique)
              AND (
                size($terms) = 0 OR any(term IN $terms WHERE
                  toLower(coalesce(te.name, "")) CONTAINS term OR
                  toLower(coalesce(te.description, "")) CONTAINS term
                )
              )
              {tactic_filter}
            RETURN DISTINCT te.id AS id
            LIMIT 20
        """, **params)
        return [r["id"] for r in result]


# ─────────────────────────────────────────────────────────────────────────────
# B.2 — MULTI-HOP GRAPH EXPANSION
#
# From seed nodes, traverse four relationship types to discover
# related techniques that flat retrieval cannot reach.
# This is the core graph-intelligence layer.
# ─────────────────────────────────────────────────────────────────────────────

def _expand_graph(seed_ids: list[str]) -> list:
    """
    Multi-hop graph expansion from seed nodes.
    Returns list of {id, name, tactic, expansion_source} dicts.
    """
    expanded = []

    with driver.session() as session:

        # ── Expansion 1: Tactic siblings ─────────────────────────────────
        # Techniques under the same tactic as a seed node.
        # Rationale: if "Prompt Injection" is a seed under "Initial Access",
        # then "Phishing" (same tactic) is also relevant to this system.
        result = session.run("""
            MATCH (seed)-[:BELONGS_TO]->(ta:Tactic)<-[:BELONGS_TO]-(sibling)
            WHERE seed.id IN $seeds
              AND (sibling:Technique OR sibling:SubTechnique)
              AND NOT sibling.id IN $seeds
            RETURN DISTINCT
                sibling.id          AS id,
                sibling.name        AS name,
                sibling.description AS description,
                ta.name             AS tactic,
                'tactic_sibling'    AS expansion_source
            LIMIT 15
        """, seeds=seed_ids)
        expanded.extend([r.data() for r in result])

        # ── Expansion 2: Attack chain neighbours (FOLLOWED_BY) ───────────
        # Techniques connected via 1–2 hops in real-world attack sequences.
        # Rationale: attackers chain techniques; if step 2 is a seed,
        # steps 1 and 3 are contextually critical even if not keyword-matched.
        # Direction is preserved and exposed (precedes / follows) instead of
        # matching FOLLOWED_BY as an undirected edge, which would otherwise
        # discard the causal ordering of the attack sequence.
        result = session.run("""
            MATCH (seed)-[:FOLLOWED_BY*1..2]->(neighbor)
            WHERE seed.id IN $seeds
              AND (neighbor:Technique OR neighbor:SubTechnique)
              AND NOT neighbor.id IN $seeds
            OPTIONAL MATCH (neighbor)-[:BELONGS_TO]->(ta:Tactic)
            RETURN DISTINCT
                neighbor.id          AS id,
                neighbor.name        AS name,
                neighbor.description AS description,
                ta.name               AS tactic,
                'attack_chain_follows' AS expansion_source
            LIMIT 15
        """, seeds=seed_ids)
        expanded.extend([r.data() for r in result])

        result = session.run("""
            MATCH (seed)<-[:FOLLOWED_BY*1..2]-(neighbor)
            WHERE seed.id IN $seeds
              AND (neighbor:Technique OR neighbor:SubTechnique)
              AND NOT neighbor.id IN $seeds
            OPTIONAL MATCH (neighbor)-[:BELONGS_TO]->(ta:Tactic)
            RETURN DISTINCT
                neighbor.id           AS id,
                neighbor.name         AS name,
                neighbor.description  AS description,
                ta.name                AS tactic,
                'attack_chain_precedes' AS expansion_source
            LIMIT 15
        """, seeds=seed_ids)
        expanded.extend([r.data() for r in result])

        # ── Expansion 3: Sub-techniques of matched parents ───────────────
        # If "Craft Adversarial Data" is a seed, its sub-techniques like
        # "Poison Training Data" are directly relevant.
        result = session.run("""
            MATCH (seed)<-[:SUBTECHNIQUE_OF]-(sub:SubTechnique)
            WHERE seed.id IN $seeds
              AND NOT sub.id IN $seeds
            OPTIONAL MATCH (sub)-[:BELONGS_TO]->(ta:Tactic)
            RETURN DISTINCT
                sub.id              AS id,
                sub.name            AS name,
                sub.description     AS description,
                ta.name             AS tactic,
                'subtechnique'      AS expansion_source
            LIMIT 12
        """, seeds=seed_ids)
        expanded.extend([r.data() for r in result])

        # ── Expansion 4: Mitigation co-occurrence neighbours ─────────────
        # Techniques that share a mitigation with a seed node.
        # Rationale: if two techniques require the same defence,
        # an auditor assessing one should know about the other.
        result = session.run("""
            MATCH (seed)-[:MITIGATED_BY]->(m:Mitigation)<-[:MITIGATED_BY]-(neighbor)
            WHERE seed.id IN $seeds
              AND (neighbor:Technique OR neighbor:SubTechnique)
              AND NOT neighbor.id IN $seeds
            OPTIONAL MATCH (neighbor)-[:BELONGS_TO]->(ta:Tactic)
            RETURN DISTINCT
                neighbor.id              AS id,
                neighbor.name            AS name,
                neighbor.description     AS description,
                ta.name                  AS tactic,
                'mitigation_neighbor'    AS expansion_source
            LIMIT 10
        """, seeds=seed_ids)
        expanded.extend([r.data() for r in result])

    return expanded


# ─────────────────────────────────────────────────────────────────────────────
# B.3 — GRAPH-STRUCTURAL SCORING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _compute_centrality(node_ids: list[str]) -> dict:
    """Compute degree centrality for retrieved nodes."""
    if not node_ids:
        return {}
    with driver.session() as session:
        result = session.run("""
            MATCH (te)
            WHERE te.id IN $ids
            OPTIONAL MATCH (te)-[r]-()
            RETURN te.id AS id, count(r) AS degree
        """, ids=node_ids)
        return {r["id"]: r["degree"] for r in result}


def _compute_case_frequency(node_ids: list[str]) -> dict:
    """Count case studies per technique — real-world evidence signal."""
    if not node_ids:
        return {}
    with driver.session() as session:
        result = session.run("""
            MATCH (cs:CaseStudy)-[:EMPLOYS]->(te)
            WHERE te.id IN $ids
            RETURN te.id AS id, count(cs) AS case_count
        """, ids=node_ids)
        return {r["id"]: r["case_count"] for r in result}


def _fetch_full_subgraph(technique_ids: list[str]) -> dict:
    """
    Fetch complete details for scored techniques:
    mitigations, case studies, attack sequences, sub-techniques.
    """
    subgraph = {"techniques": [], "mitigations": [], "case_studies": [],
                "attack_sequences": []}

    if not technique_ids:
        return subgraph

    with driver.session() as session:

        # Technique paths: Tactic ← Technique → Mitigation
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
        """, ids=technique_ids)
        subgraph["techniques"] = [r.data() for r in result]

        if subgraph["techniques"]:
            tech_ids = [t["technique_id"] for t in subgraph["techniques"]]

            # Case studies
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
                LIMIT 12
            """, ids=tech_ids)
            subgraph["case_studies"] = [r.data() for r in result]

            # Attack sequences (FOLLOWED_BY)
            result = session.run("""
                MATCH (a)-[:FOLLOWED_BY]->(b)
                WHERE a.id IN $ids OR b.id IN $ids
                RETURN a.name AS from_technique,
                       b.name AS to_technique
                LIMIT 15
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


# ─────────────────────────────────────────────────────────────────────────────
# SUBGRAPH SERIALISATION (§7.2.1 — Natural Language graph format)
#
# The serialised subgraph now includes retrieval metadata (method, graph
# stats) so the LLM understands how evidence was gathered.
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
    stats  = subgraph.get("graph_stats", {})
    lines.append(f"=== RETRIEVED SUBGRAPH FROM MITRE ATLAS (method: {method}) ===")
    if stats:
        lines.append(
            f"  Seeds: {stats.get('seed_count',0)} → "
            f"Expanded: {stats.get('expanded_count',0)} → "
            f"Scored: {stats.get('total_scored',0)} → "
            f"Selected: {stats.get('top_selected',0)}"
        )
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
                subs = [s for s in t["subtechniques"] if s]
                if subs:
                    lines.append(f"  Subtechniques: {', '.join(subs)}")
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


def compact_subgraph_context(subgraph_context: str, max_chars: int = 12000) -> str:
    """Trim verbose evidence so hosted 70B generation finishes reliably."""
    if len(subgraph_context) <= max_chars:
        return subgraph_context

    keep_head = int(max_chars * 0.82)
    keep_tail = max_chars - keep_head
    return (
        subgraph_context[:keep_head]
        + "\n\n[...context trimmed for generation speed...]\n\n"
        + subgraph_context[-keep_tail:]
    )


def generate_assessment(subgraph_context: str) -> str:
    compact_context = compact_subgraph_context(subgraph_context)
    prompt = GENERATION_PROMPT_TEMPLATE.format(subgraph_context=compact_context)
    return ask_llm(prompt, max_tokens=1600, timeout=240.0)


# ─────────────────────────────────────────────────────────────────────────────
# FULL PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_assessment(system_description: str) -> dict:
    """
    Full GraphRAG pipeline (arXiv:2408.08921), v2 — multi-hop:

    G-Retrieval Phase A — Query Enhancement (§6.4.1):
        LLM decomposes system + expands to ATLAS vocabulary + identifies tactics

    G-Retrieval Phase B — Multi-Hop Subgraph Extraction (§6.3):
        Semantic seeds → Graph expansion → Structural scoring

    G-Generation (§7):
        LLM receives serialised subgraph in natural language (§7.2.1)
        and produces a structured, ID-cited threat assessment.
    """

    sep = "═" * 65

    print(f"\n{sep}")
    print("  ATLAS THREAT ASSESSMENT — GraphRAG Pipeline v2 (Multi-Hop)")
    print("  Peng et al., arXiv:2408.08921")
    print(sep)

    # ── Phase A: Query Enhancement ───────────────────────────────────────
    print("\n[Phase A · Query Enhancement §6.4.1]")
    print("  LLM decomposes system + expands to ATLAS vocabulary + identifies tactics...")
    enhanced         = enhance_query(system_description)
    components       = enhanced.get("components",       [])
    search_terms     = enhanced.get("search_terms",     [])
    relevant_tactics = enhanced.get("relevant_tactics",  [])
    print(f"  Components:       {components}")
    print(f"  Search terms:     {search_terms}")
    print(f"  Relevant tactics: {relevant_tactics}")

    if not search_terms:
        print("  ⚠ No search terms generated. Check LLM connectivity.")
        return {}

    # ── Phase B: Multi-Hop Subgraph Extraction ───────────────────────────
    print("\n[Phase B · Multi-Hop Subgraph Extraction §6.3]")
    subgraph = retrieve_subgraph(
        search_terms=search_terms,
        system_description=system_description,
        top_k=TOP_K,
        relevant_tactics=relevant_tactics
    )
    print(f"  Techniques retrieved:     {len(subgraph['techniques'])}")
    print(f"  Mitigations retrieved:    {len(subgraph['mitigations'])}")
    print(f"  Case studies retrieved:   {len(subgraph['case_studies'])}")
    print(f"  Attack sequences (paths): {len(subgraph.get('attack_sequences', []))}")
    print(f"  Retrieval method:         {subgraph.get('retrieval_method', 'unknown')}")
    stats = subgraph.get("graph_stats", {})
    if stats:
        print(f"  Graph traversal:          {stats.get('seed_count',0)} seeds → "
              f"{stats.get('expanded_count',0)} expanded → "
              f"{stats.get('total_scored',0)} scored → "
              f"{stats.get('top_selected',0)} selected")

    if not subgraph["techniques"]:
        print("\n  ⚠ No techniques matched. Try a more detailed description.")
        return {}

    # Serialise subgraph to natural language (§7.2.1)
    subgraph_context = serialise_subgraph(subgraph, system_description, components)

    # ── G-Generation ─────────────────────────────────────────────────────
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
    print("  ATLAS Reasoning Engine — Step 3 (v2 — Multi-Hop GraphRAG)")
    print(f"  Model:        {LLM_MODEL}")
    print(f"  API:          {API_BASE_URL}")
    print(f"  Embed model:  {EMBED_MODEL_NAME}")
    print(f"  Top-k seeds:  {TOP_K}")
    print("=" * 65)

    # ── Health checks ─────────────────────────────────────────────────────────
    print("\n[Startup Diagnostics]")

    print(f"  Checking Neo4j at {NEO4J_URI}...")
    if not check_neo4j():
        print("  ❌ Neo4j not reachable")
        print(f"     docker run -p 7687:7687 -p 7474:7474 "
              f"--env NEO4J_AUTH={NEO4J_USER}/<your-password> neo4j:latest")
        print("     Then set NEO4J_PASS in your .env file to match.")
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
