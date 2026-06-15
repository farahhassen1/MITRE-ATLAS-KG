# MITRE ATLAS — Queryable Knowledge Graph

A queryable knowledge graph of MITRE ATLAS built with Neo4j.
Enables auditors and security engineers to ask structured questions
about adversarial AI threats grounded in the graph.

## Graph statistics

| Element | Count |
|---|---|
| Tactics | 16 |
| Techniques | 170 |
| Mitigations | 35 |
| Case Studies | 57 |
| EMPLOYS relationships | 449 |
| MITIGATED_BY relationships | 246 |
| BELONGS_TO relationships | 111 |

## Schema

(CaseStudy)-[:EMPLOYS]->(Technique)-[:BELONGS_TO]->(Tactic)

(Technique)-[:MITIGATED_BY]->(Mitigation)

(SubTechnique)-[:SUBTECHNIQUE_OF]->(Technique)

(Technique)-[:FOLLOWED_BY]->(Technique)

(Technique)-[:TARGETS]->(Platform)

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
Open http://localhost:7474 and copy queries from `queries.cypher`

## Ingestion strategy

Two-file approach:
- **v6 YAML** (`Data/v6/ATLAS-2026.05.yaml`) — tactics, techniques,
  case studies, attack sequence relationships
- **Legacy YAML** (`Data/legacy/ATLAS-5.6.0.yaml`) — mitigation→technique
  links which are absent from the v6 format

## Design choices

**Why Neo4j?**
ATLAS data is inherently graph-structured. A relational database
would require complex JOIN chains to answer questions like
"give me the full path from tactic to technique to mitigation".
Neo4j's native graph traversal makes this a single Cypher statement.

**Why this schema?**
Four primary node types mirror the ATLAS taxonomy directly:
Tactic, Technique, Mitigation, CaseStudy. SubTechnique is modelled
as a separate label to distinguish parent-child technique hierarchies.
Relationships are typed and directional so queries read naturally.

**Why two YAML files?**
The v6 format dropped the techniques field from mitigations.
The legacy 5.6.0 file preserves those links. Combining both files
gives a complete graph with no missing edges.

## Example queries

**Q1 — Which techniques appear most in real attacks?**
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

**Q3 — Which techniques have no mitigation?**
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

**Q5 — Voyverse's question: techniques targeting RAG inference**
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
RETURN ta.name AS tactic,
       te.name AS technique,
       collect(m.name) AS mitigations
ORDER BY ta.name
```

## Tools used
- Neo4j Community Edition
- Python 3.10 + PyYAML
- Claude (Anthropic) — assisted with schema design and ingestion logic

