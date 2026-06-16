# MITRE ATLAS GraphRAG Threat Assessment

This project builds a Neo4j knowledge graph from MITRE ATLAS data and uses it to generate grounded AI threat assessments.

The workflow is simple:

1. Load MITRE ATLAS into Neo4j.
2. Describe an AI system.
3. Retrieve relevant ATLAS techniques, mitigations, case studies, and attack paths.
4. Generate a cited threat report from the retrieved graph evidence.

## What It Does

- Builds a queryable MITRE ATLAS graph in Neo4j.
- Supports semantic and graph-based retrieval.
- Uses an OpenAI-compatible LLM endpoint for query expansion and report generation.
- Produces reports with ATLAS IDs such as `[AML.T0051]` and `[AML.M0015]`.
- Provides both a CLI engine and a Flask web interface.

## Main Files

| File | Purpose |
|---|---|
| `ingestion.py` | Loads ATLAS YAML data into Neo4j |
| `reasoning_engine.py` | Core GraphRAG retrieval and generation pipeline |
| `app.py` | Flask web UI backend |
| `templates/index.html` | Web UI page |
| `static/js/app.js` | Web UI logic |
| `static/css/style.css` | Web UI styling |
| `queries.cypher` | Example graph queries |
| `requirements.txt` | Python dependencies |

## Requirements

- Python 3.10+
- Neo4j running locally
- OpenAI-compatible LLM API endpoint
- A `.env` file with Neo4j and LLM credentials

## Setup

Install dependencies:

```powershell
pip install -r requirements.txt
```

Create `.env`:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=your_neo4j_password

API_BASE_URL=https://your-openai-compatible-endpoint/api
API_KEY=your_api_key
LLM_MODEL=your_model_name
VERIFY_SSL=true
```

Start Neo4j, then load the graph:

```powershell
python ingestion.py
```

## Run

### Web UI

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5050
```

Health check:

```text
http://127.0.0.1:5050/health
```

### CLI Engine

```powershell
python reasoning_engine.py
```

## Pipeline

### 1. Query Enhancement

The LLM decomposes the system description into components and ATLAS search terms.

Example:

```text
RAG chatbot -> prompt injection, RAG poisoning, model stealing, data leakage
```

### 2. Graph Retrieval

The engine retrieves:

- techniques
- mitigations
- case studies
- attack sequences
- tactic relationships

Retrieval is grounded in Neo4j, not free-text guessing.

### 3. Generation

The LLM receives only the retrieved subgraph and produces a cited report. If the LLM is slow or returns empty text, the web app builds a fallback report from the retrieved graph evidence.

## Example Output

```text
Techniques retrieved: 22
Mitigations retrieved: 18
Case studies retrieved: 12
Attack paths retrieved: 15

## THREAT ASSESSMENT REPORT

### Top Threats
- [AML.T0051] Prompt Injection ...
- [AML.T0054] LLM Jailbreak ...
```

## Troubleshooting

### Neo4j is not reachable

Check that Neo4j is running and `.env` has the correct password.

```powershell
python ingestion.py
```

### LLM API is not reachable

Check:

- `API_BASE_URL`
- `API_KEY`
- `LLM_MODEL`
- internet/network access
- `VERIFY_SSL`

### Generation is slow

The hosted 70B model can be slow on large prompts. The app trims context and uses a fallback report if needed.

### Browser shows old behavior

Use the current web port:

```text
http://127.0.0.1:5050
```

Then hard refresh:

```text
Ctrl+F5
```

Check `/health`; it should include `app_version`.

## Notes

- Do not commit `.env`.
- Run ingestion again if the graph database is empty or reset.
- Reports are saved under `assessments/`.
