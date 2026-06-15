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

## Tools used

- Neo4j Community Edition — graph storage and Cypher query engine
<<<<<<< HEAD
- Python 3.10 + PyYAML — YAML parsing and graph ingestion
=======
- Python 3.10 + PyYAML — YAML parsing and graph ingestion
>>>>>>> bc7785955e5ca0c4228e274f1db827b4793ded1e
