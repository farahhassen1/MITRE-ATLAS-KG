"""
app.py
ATLAS Reasoning Engine — Flask Web Interface
Voyverse Technical Assessment · Step 3 (Reasoning Engine + Document Drafting)

Routes:
  GET  /           → serve the SPA
  GET  /health     → JSON health check (Neo4j + LLM API)
  POST /assess     → SSE stream of the full GraphRAG pipeline
  POST /export     → generate and download a formatted threat-modelling report
"""

import os
import json
import time
import datetime
import threading
from flask import Flask, Response, request, jsonify, render_template, stream_with_context
from flask_cors import CORS

# Import reasoning engine components
import reasoning_engine as re_engine

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def sse_event(event: str, data: dict) -> str:
    """Format a server-sent event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    """Quick health check for Neo4j and LLM API."""
    neo4j_ok = re_engine.check_neo4j()
    api_ok   = re_engine.check_api_endpoint()
    return jsonify({
        "neo4j": neo4j_ok,
        "llm_api": api_ok,
        "model": re_engine.LLM_MODEL,
        "api_base": re_engine.API_BASE_URL,
    })


@app.route("/assess", methods=["POST"])
def assess():
    """
    SSE endpoint: streams GraphRAG pipeline progress events then the final report.
    Each SSE event has a named type and a JSON data payload.
    """
    body = request.get_json(force=True)
    system_description = (body.get("description") or "").strip()
    if not system_description:
        return jsonify({"error": "No system description provided."}), 400

    def generate():
        try:
            # ── Stage 1: Query Enhancement ────────────────────────────────
            yield sse_event("stage", {"stage": 1, "label": "Query Enhancement",
                                       "detail": "LLM decomposing system and expanding to ATLAS vocabulary…"})

            enhanced = re_engine.enhance_query(system_description)
            components   = enhanced.get("components",   [])
            search_terms = enhanced.get("search_terms", [])

            yield sse_event("enhancement", {
                "components":   components,
                "search_terms": search_terms,
            })

            if not search_terms:
                yield sse_event("error", {"message": "No search terms generated. Check LLM connectivity."})
                return

            # ── Stage 2: Subgraph Extraction ──────────────────────────────
            yield sse_event("stage", {"stage": 2, "label": "Subgraph Extraction",
                                       "detail": "Running Cypher queries against ATLAS graph…"})

            subgraph = re_engine.retrieve_subgraph(search_terms)

            yield sse_event("subgraph", {
                "techniques":      len(subgraph["techniques"]),
                "mitigations":     len(subgraph["mitigations"]),
                "case_studies":    len(subgraph["case_studies"]),
                "attack_sequences": len(subgraph.get("attack_sequences", [])),
                "data": {
                    "techniques":  subgraph["techniques"],
                    "mitigations": subgraph["mitigations"],
                    "case_studies": subgraph["case_studies"],
                    "attack_sequences": subgraph.get("attack_sequences", []),
                }
            })

            if not subgraph["techniques"]:
                yield sse_event("error", {"message": "No techniques matched. Try a more detailed description."})
                return

            # ── Stage 3: G-Generation ─────────────────────────────────────
            yield sse_event("stage", {"stage": 3, "label": "G-Generation",
                                       "detail": f"Sending subgraph to {re_engine.LLM_MODEL}…"})

            subgraph_context = re_engine.serialise_subgraph(subgraph, system_description, components)
            assessment       = re_engine.generate_assessment(subgraph_context)

            # Save assessment to disk
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("assessments", exist_ok=True)
            save_path = os.path.join("assessments", f"assessment_{ts}.json")
            payload = {
                "timestamp":          ts,
                "system_description": system_description,
                "components":         components,
                "search_terms":       search_terms,
                "subgraph":           subgraph,
                "assessment":         assessment,
            }
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)

            yield sse_event("result", {
                "assessment":  assessment,
                "components":  components,
                "search_terms": search_terms,
                "subgraph":    {
                    "techniques":  subgraph["techniques"],
                    "mitigations": subgraph["mitigations"],
                    "case_studies": subgraph["case_studies"],
                    "attack_sequences": subgraph.get("attack_sequences", []),
                },
                "save_path": save_path,
            })

            yield sse_event("done", {"message": "Assessment complete."})

        except Exception as exc:
            import traceback
            yield sse_event("error", {"message": str(exc), "trace": traceback.format_exc()})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/export", methods=["POST"])
def export_report():
    """
    Generate a standalone HTML threat-modelling report document
    with traceable citations and professional formatting.
    Returns the HTML as a downloadable file.
    """
    from report_generator import generate_html_report

    body = request.get_json(force=True)
    assessment   = body.get("assessment", "")
    components   = body.get("components", [])
    search_terms = body.get("search_terms", [])
    subgraph     = body.get("subgraph", {})
    system_desc  = body.get("system_description", "")

    html = generate_html_report(
        system_description=system_desc,
        assessment=assessment,
        components=components,
        search_terms=search_terms,
        subgraph=subgraph,
    )

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ATLAS_Threat_Report_{ts}.html"

    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.route("/demo")
def demo_description():
    """Return the built-in demo system description."""
    return jsonify({"description": re_engine.DEMO_SYSTEM})


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("="*60)
    print("  ATLAS Reasoning Engine + Document Drafting — Web UI")
    print("  http://localhost:5000")
    print("="*60)
    app.run(debug=True, threaded=True, port=5000)
