# MITRE ATLAS — Queryable Knowledge Graph

A queryable knowledge graph of MITRE ATLAS built with Neo4j.
Enables auditors and security engineers to ask structured questions
about adversarial AI threats grounded in the graph — not free-text LLM responses.

---

## Graph statistics

| Element | Count |
|---|---|
| Tactics | 16 |
| Techniques | 101 |
| SubTechniques | 69 |
| Mitigations | 35 |
| Case Studies | 57 |
| Platforms | 4 |
| EMPLOYS | 449 |
| TARGETS | 335 |
| FOLLOWED_BY | 328 |
| MITIGATED_BY | 246 |
| BELONGS_TO | 111 |
| SUBTECHNIQUE_OF | 69 |


## Schema
(CaseStudy)-[:EMPLOYS]->(Technique)-[:BELONGS_TO]->(Tactic)

(Technique)-[:MITIGATED_BY]->(Mitigation)

(Technique)-[:TARGETS]->(Platform)

(Technique)-[:FOLLOWED_BY]->(Technique)

(SubTechnique)-[:SUBTECHNIQUE_OF]->(Technique)

(SubTechnique)-[:BELONGS_TO]->(Tactic)

(SubTechnique)-[:MITIGATED_BY]->(Mitigation)

## Setup

### Option A — Neo4j Desktop
1. Download Neo4j Desktop from https://neo4j.com/download/
2. Create a new database and start it
3. Note your password

### Option B — Docker
```bash
docker run -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:latest
```

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run ingestion
```bash
python ingestion.py
```

Expected output:
✅ Database cleared

✅ Constraints created

✅ Nodes loaded

✅ Relationships loaded

### Run queries

Open http://localhost:7474 and copy queries from `queries.cypher`.

---

## Ingestion strategy

Two-file approach combining:

- **v6 YAML** (`Data/v6/ATLAS-2026.05.yaml`) — current format containing
  tactics, techniques, case studies, and attack sequence relationships
  (EMPLOYS with step-level procedure descriptions and leads-to chains)
- **Legacy YAML** (`Data/legacy/ATLAS-5.6.0.yaml`) — older format preserved
  for its mitigation→technique links, which were dropped from the v6 format,
  and for reliable BELONGS_TO (Technique → Tactic) edges

This two-file strategy was a necessary engineering decision: the v6 format
is richer for techniques and case studies; the legacy format is the only
reliable source for mitigation-to-technique mapping. Combining both produces
a complete graph with no missing edges.

---

## Design choices

**Why Neo4j?**
ATLAS data is inherently graph-structured. A relational database would require
complex multi-table JOINs to answer questions like "give me the full path from
tactic to technique to mitigation across all real incidents." Neo4j's native
graph traversal makes this a single readable Cypher statement. Variable-length
path queries (FOLLOWED_BY chains modelling multi-step attack sequences) have
no natural equivalent in SQL.

**Why separate Technique and SubTechnique labels?**
Modelling SubTechniques as a distinct node label rather than a boolean flag
allows queries to target either level independently. The SUBTECHNIQUE_OF
relationship makes the parent-child hierarchy explicit and traversable.
This matters for auditors: a technique like "Craft Adversarial Data" has
sub-techniques with meaningfully different threat profiles and mitigations.

**Why two YAML files?**
The v6 format dropped the `techniques` field from mitigation objects, making
it impossible to build MITIGATED_BY edges from v6 alone. The legacy 5.6.0
file preserves those links. Combining both files gives a complete graph with
no missing edges.

---

## Example queries

**Q1 — Which techniques appear most in real-world attacks?**
```cypher
MATCH (c:CaseStudy)-[:EMPLOYS]->(te)
WHERE te:Technique OR te:SubTechnique
RETURN te.name, count(c) AS nb_cases
ORDER BY nb_cases DESC
LIMIT 10
```

**Q2 — Full threat path: Tactic → Technique → Mitigation**
```cypher
MATCH (ta:Tactic)<-[:BELONGS_TO]-(te)-[:MITIGATED_BY]->(m:Mitigation)
RETURN ta.name AS tactic, te.name AS technique, m.name AS mitigation
ORDER BY ta.name
LIMIT 20
```

**Q3 — Which techniques have no mitigation documented?**
```cypher
MATCH (te)
WHERE (te:Technique OR te:SubTechnique)
  AND NOT (te)-[:MITIGATED_BY]->(:Mitigation)
RETURN te.name AS unmitigated_technique
ORDER BY te.name
```

**Q4 — Which tactic is most targeted in real attacks?**
```cypher
MATCH (c:CaseStudy)-[:EMPLOYS]->(te)-[:BELONGS_TO]->(ta:Tactic)
RETURN ta.name, count(DISTINCT c) AS nb_attacks
ORDER BY nb_attacks DESC
```

**Q5 — Voyverse's question: techniques targeting RAG inference + mitigations**
```cypher
MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
WHERE (te:Technique OR te:SubTechnique)
  AND (
       toLower(te.description) CONTAINS "rag"
    OR toLower(te.description) CONTAINS "retrieval"
    OR toLower(te.description) CONTAINS "inference"
    OR toLower(te.description) CONTAINS "language model"
  )
OPTIONAL MATCH (te)-[:MITIGATED_BY]->(m:Mitigation)
RETURN ta.name         AS tactic,
       te.name         AS technique,
       collect(m.name) AS mitigations
ORDER BY ta.name
```

---

## Project structure

MITRE ATLAS/

├── Data/

│   ├── legacy/

│   │   └── ATLAS-5.6.0.yaml

│   └── v6/

│       └── ATLAS-2026.05.yaml

├── ingestion.py

├── queries.cypher

├── requirements.txt

└── README.md

---

## Step 3 — Reasoning Engine (GraphRAG Pipeline)

### Overview

The **reasoning engine** (§3 of Voyverse assessment) implements a three-stage **GraphRAG** pipeline
(Peng et al., arXiv:2408.08921) that consumes a natural-language description of an AI system
and produces a **structured threat assessment grounded in the graph**.

**Key principle**: The LLM receives ONLY the extracted subgraph and cannot hallucinate.
Every claim in the output must cite a graph node ID.

### Architecture

**Stage 1: Query Enhancement (§6.4.1)**
- LLM decomposes system description into security-relevant components
- Expands each component into ATLAS vocabulary search terms
- Example: "RAG-based chatbot" → ["RAG poisoning", "model inversion", "prompt injection", ...]

**Stage 2: Subgraph Extraction (§6.3)**
- Three Cypher queries retrieve:
  - Techniques + paths to tactics and mitigations
  - Real-world case studies employing matched techniques
  - Attack sequences (FOLLOWED_BY chains)
- **Retrieval granularity**: subgraph (nodes + triplets + paths)

**Stage 3: Generation (§7)**
- LLM receives **serialised subgraph in natural language** (§7.2.1)
- Produces structured, **ID-cited threat assessment** with 7 sections:
  1. System Summary
  2. Identified Threats
  3. Applicable Mitigations
  4. Real-World Precedents
  5. Attack Sequences
  6. Risk Table
  7. Coverage Gaps

### Files

- **reasoning_engine.py** — Core GraphRAG pipeline (570 lines)
  - `enhance_query()` — LLM query enhancement
  - `retrieve_subgraph()` — Cypher-based subgraph extraction
  - `generate_assessment()` — LLM-based threat report generation
  - Health checks for Neo4j and API endpoint

- **interface.py** — User-friendly menu system (340 lines)
  - Demo assessment (pre-loaded chatbot system)
  - Custom system description input
  - Assessment history tracking
  - Export to JSON and Markdown
  - Clean formatted output

### Setup

#### 1. Install dependencies
```bash
pip install neo4j openai httpx python-dotenv
```

#### 2. Create .env file
```bash
# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=password

# Remote LLM API (OpenAI-compatible)
API_BASE_URL=https://tokenfactory.esprit.tn/api
API_KEY=your_api_key_here
LLM_MODEL=hosted_vllm/Llama-3.1-70B-Instruct
```

#### 3. Start Neo4j (if not running)
```bash
docker run -p 7687:7687 -p 7474:7474 \
  --env NEO4J_AUTH=neo4j/29703391 \
  neo4j:latest
```

#### 4. Run ingestion (one-time)
```bash
python ingestion.py
```

### Usage

#### Option A — Interactive menu
```bash
python interface.py
```
Menu options:
1. Run demo assessment (RAG chatbot system)
2. Describe custom AI system
3. View assessment history
4. Export last assessment
5. Exit

#### Option B — Direct engine (for scripting)
```bash
python reasoning_engine.py
```
Runs demo assessment + interactive custom mode

### Example Output

```
[G-Retrieval / Query Enhancement §6.4.1]
  Components identified: ['LLM backbone', 'vector database', 'API gateway', ...]
  Search terms generated: ['RAG poisoning', 'prompt injection', 'model stealing', ...]

[G-Retrieval / Subgraph Extraction §6.3]
  Techniques retrieved: 22
  Mitigations retrieved: 31
  Case studies retrieved: 8
  Attack sequences: 12

[G-Generation §7]
  ## THREAT ASSESSMENT REPORT
  
  ### 1. System Summary
  A RAG-based customer support chatbot with public API, fine-tuned LLM, 
  vector database, and sensitive data handling...
  
  ### 2. Identified Threats
  - [AML.T0051] Prompt Injection (Tactic: Execution)
    Attackers can inject malicious prompts into user queries to manipulate
    LLM responses. Likelihood: HIGH
  ...
```

### Design choices

**Why OpenAI-compatible API instead of local Ollama?**
- Remote hosted LLM (vLLM) provides consistent, fast inference (5-10s vs 180s+)
- Better for large context windows (subgraph serialization can be verbose)
- Scales horizontally if needed

**Why serialize subgraph as natural language?**
- Paper §7.2.1 identifies NL as the optimal format for LM generators
- Preserves graph structure (node IDs, relationships) while being human-readable
- Prevents the LLM from inventing entities not in the subgraph

**Why cite by graph node ID?**
- Every threat must be traceable to ATLAS
- Prevents hallucination: if a node isn't in the subgraph, it can't appear in output
- Enables verification and audit trails

---

## Tools used

- **Neo4j Community Edition** — graph storage and Cypher query engine
- **Python 3.13** + libraries:
  - `neo4j` — Python driver for Neo4j
  - `openai` — OpenAI-compatible API client
  - `httpx` — HTTP client with TLS/SSL control
  - `pyyaml` — YAML parsing and ingestion
  - `sentence-transformers` — (optional) semantic embeddings for v2 retrieval
