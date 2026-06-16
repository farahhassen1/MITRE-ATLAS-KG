"""
app.py
ATLAS Reasoning Engine - Flask Web Interface

Routes:
  GET  /        serve the UI
  GET  /health  check Neo4j and LLM
  POST /assess  stream the GraphRAG pipeline with SSE
  POST /export  generate an HTML report
  GET  /demo    return the demo system description
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import json
import os
import sys
import traceback
from typing import Any, Callable

from flask import Flask, Response, jsonify, make_response, render_template, request, stream_with_context
from flask_cors import CORS


# ---------------------------------------------------------------------------
# Process/console hardening
# ---------------------------------------------------------------------------

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")


def console_safe(value: Any) -> str:
    """
    Return text that the Windows legacy console can always encode.

    The original crash was UnicodeEncodeError from a console write, not from
    Neo4j retrieval itself. This function removes the known star character and
    escapes anything else that cannot be represented as ASCII.
    """
    text = str(value).replace("\u2605", "")
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


class SafeConsole:
    encoding = "ascii"

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def write(self, value):
        return self._wrapped.write(console_safe(value))

    def flush(self):
        return self._wrapped.flush()

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class SilentConsole:
    encoding = "ascii"

    def write(self, value):
        return len(str(value))

    def flush(self):
        return None

    def isatty(self):
        return False


for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")

sys.stdout = SafeConsole(sys.stdout)
sys.stderr = SafeConsole(sys.stderr)
sys.__stdout__ = sys.stdout
sys.__stderr__ = sys.stderr

import builtins

_real_print = builtins.print


def safe_print(*args, **kwargs):
    _real_print(*(console_safe(arg) for arg in args), **kwargs)


builtins.print = safe_print


# Import after console hardening so import-time logs cannot crash the app.
import reasoning_engine as re_engine


app = Flask(__name__)
CORS(app)

APP_VERSION = "atlas-web-ascii-safe-20260616-3"
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4)
STAGE_TIMEOUT_SECONDS = 300
HEARTBEAT_INTERVAL_SECONDS = 5


# ---------------------------------------------------------------------------
# Sanitizing and SSE helpers
# ---------------------------------------------------------------------------

def sanitize(value: Any) -> Any:
    """Remove problematic characters from nested payloads sent to the browser."""
    if isinstance(value, str):
        return value.replace("\u2605", "")
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize(item) for item in value)
    if isinstance(value, dict):
        return {sanitize(key): sanitize(item) for key, item in value.items()}
    return value


def sse_event(event: str, data: dict[str, Any]) -> str:
    payload = json.dumps(sanitize(data), ensure_ascii=True)
    return f"event: {event}\ndata: {payload}\n\n"


def sse_heartbeat() -> str:
    return ": heartbeat\n\n"


def run_stage(fn: Callable, *args, **kwargs):
    """
    Run a blocking stage with stdout/stderr silenced.

    Any progress logging from Neo4j, sentence-transformers, or our own prints
    is intentionally discarded here. The UI receives explicit SSE events.
    """
    silent = SilentConsole()
    original_print = builtins.print
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    original_dunder_stdout = sys.__stdout__
    original_dunder_stderr = sys.__stderr__
    try:
        builtins.print = lambda *print_args, **print_kwargs: None
        sys.stdout = silent
        sys.stderr = silent
        sys.__stdout__ = silent
        sys.__stderr__ = silent
        return sanitize(fn(*args, **kwargs))
    finally:
        builtins.print = original_print
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        sys.__stdout__ = original_dunder_stdout
        sys.__stderr__ = original_dunder_stderr


def run_with_heartbeat(fn: Callable, *args, timeout: int = STAGE_TIMEOUT_SECONDS, **kwargs):
    future = EXECUTOR.submit(run_stage, fn, *args, **kwargs)
    elapsed = 0

    while True:
        try:
            yield ("result", future.result(timeout=HEARTBEAT_INTERVAL_SECONDS))
            return
        except concurrent.futures.TimeoutError:
            elapsed += HEARTBEAT_INTERVAL_SECONDS
            if elapsed >= timeout:
                future.cancel()
                raise TimeoutError(
                    f"{getattr(fn, '__name__', 'pipeline stage')} exceeded {timeout}s. "
                    "Check Neo4j, the embedding model, and the LLM endpoint."
                )
            yield ("heartbeat", sse_heartbeat())


def stage_result(fn: Callable, *args, **kwargs):
    result = None
    for kind, value in run_with_heartbeat(fn, *args, **kwargs):
        if kind == "heartbeat":
            yield value
        else:
            result = value
    return result


def build_fallback_assessment(
    system_description: str,
    components: list[str],
    subgraph: dict[str, Any],
) -> str:
    """Create a deterministic report if the remote LLM is slow or empty."""
    techniques = subgraph.get("techniques", [])[:8]
    mitigations = subgraph.get("mitigations", [])[:8]
    sequences = subgraph.get("attack_sequences", [])[:3]

    lines = [
        "## THREAT ASSESSMENT REPORT",
        "",
        "### 1. System Summary",
        (
            "The assessed system includes "
            + (", ".join(components[:8]) if components else "the submitted AI system")
            + ". The retrieved MITRE ATLAS subgraph identifies the following priority threats and controls."
        ),
        "",
        "### 2. Top Threats",
    ]

    if techniques:
        for tech in techniques:
            tech_id = tech.get("technique_id", "")
            name = tech.get("technique", "Unnamed technique")
            tactic = tech.get("tactic", "Unknown")
            desc = (tech.get("description") or "").strip()
            why = desc[:220] + ("..." if len(desc) > 220 else "")
            lines.append(
                f"- **[{tech_id}] {name}** (Tactic: {tactic}) - "
                f"Applies because the system exposes related components or data flows. {why} "
                "Likelihood: Medium."
            )
    else:
        lines.append("- No techniques were retrieved from the ATLAS graph.")

    lines.extend(["", "### 3. Priority Mitigations"])
    if mitigations:
        for mitigation in mitigations:
            mit_id = mitigation.get("id", "")
            name = mitigation.get("name", "Unnamed mitigation")
            desc = (mitigation.get("desc") or "").strip()
            detail = desc[:180] + ("..." if len(desc) > 180 else "")
            lines.append(
                f"- **[{mit_id}] {name}** - {detail} Owner: Security Operations / ML Engineer."
            )
    else:
        lines.append("- No mitigations were retrieved for the matched techniques.")

    lines.extend(["", "### 4. Attack Sequences"])
    if sequences:
        for seq in sequences:
            lines.append(
                f"- {seq.get('from_technique', 'Unknown technique')} -> "
                f"{seq.get('to_technique', 'Unknown technique')}"
            )
    else:
        lines.append("- No attack paths were retrieved.")

    lines.extend(
        [
            "",
            "### 5. Risk Table",
            "| Technique ID | Technique | Tactic | Likelihood | Mitigations |",
            "|---|---|---|---|---|",
        ]
    )
    mitigation_ids = ", ".join(
        f"[{m.get('id')}]" for m in mitigations[:3] if m.get("id")
    ) or "None retrieved"
    for tech in techniques:
        lines.append(
            f"| [{tech.get('technique_id', '')}] | {tech.get('technique', '')} | "
            f"{tech.get('tactic', '')} | Medium | {mitigation_ids} |"
        )

    lines.extend(["", "### 6. Coverage Gaps"])
    lines.append(
        "Review components not explicitly represented in the retrieved subgraph: "
        + (", ".join(components[8:]) if len(components) > 8 else "none identified from query enhancement.")
    )

    lines.append("")
    lines.append(
        "_Note: This report was generated locally from the retrieved ATLAS subgraph because the remote LLM did not return report text in time._"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    response = make_response(render_template("index.html"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/health")
def health():
    return jsonify(
        {
            "neo4j": re_engine.check_neo4j(),
            "llm_api": re_engine.check_api_endpoint(),
            "model": re_engine.LLM_MODEL,
            "api_base": re_engine.API_BASE_URL,
            "app_version": APP_VERSION,
        }
    )


@app.route("/demo")
def demo_description():
    return jsonify({"description": re_engine.DEMO_SYSTEM})


@app.route("/assess", methods=["POST"])
def assess():
    body = request.get_json(force=True) or {}
    system_description = (body.get("description") or "").strip()

    if not system_description:
        return jsonify({"error": "No system description provided."}), 400

    def stream():
        try:
            yield sse_event(
                "stage",
                {
                    "stage": 1,
                    "label": "Query Enhancement",
                    "detail": "LLM decomposing system and expanding to ATLAS vocabulary...",
                },
            )

            enhanced = yield from stage_result(re_engine.enhance_query, system_description)
            enhanced = enhanced or {}
            components = enhanced.get("components", [])
            search_terms = enhanced.get("search_terms", [])
            relevant_tactics = enhanced.get("relevant_tactics", [])

            yield sse_event(
                "enhancement",
                {
                    "components": components,
                    "search_terms": search_terms,
                    "relevant_tactics": relevant_tactics,
                },
            )

            if not search_terms:
                yield sse_event(
                    "error",
                    {
                        "stage": 1,
                        "message": "No search terms generated. Check LLM connectivity.",
                    },
                )
                return

            yield sse_event(
                "stage",
                {
                    "stage": 2,
                    "label": "Subgraph Extraction",
                    "detail": "Running Cypher queries against ATLAS graph...",
                },
            )

            subgraph = yield from stage_result(
                re_engine.retrieve_subgraph,
                search_terms=search_terms,
                system_description=system_description,
                relevant_tactics=relevant_tactics,
            )
            subgraph = subgraph or {
                "techniques": [],
                "mitigations": [],
                "case_studies": [],
                "attack_sequences": [],
                "retrieval_method": "",
                "graph_stats": {},
            }

            yield sse_event(
                "subgraph",
                {
                    "techniques": len(subgraph.get("techniques", [])),
                    "mitigations": len(subgraph.get("mitigations", [])),
                    "case_studies": len(subgraph.get("case_studies", [])),
                    "attack_sequences": len(subgraph.get("attack_sequences", [])),
                    "retrieval_method": subgraph.get("retrieval_method", ""),
                    "graph_stats": subgraph.get("graph_stats", {}),
                    "data": {
                        "techniques": subgraph.get("techniques", []),
                        "mitigations": subgraph.get("mitigations", []),
                        "case_studies": subgraph.get("case_studies", []),
                        "attack_sequences": subgraph.get("attack_sequences", []),
                    },
                },
            )

            if not subgraph.get("techniques"):
                yield sse_event(
                    "error",
                    {
                        "stage": 2,
                        "message": "No techniques matched. Try a more detailed description.",
                    },
                )
                return

            yield sse_event(
                "stage",
                {
                    "stage": 3,
                    "label": "G-Generation",
                    "detail": f"Sending subgraph to {re_engine.LLM_MODEL}...",
                },
            )

            subgraph_context = re_engine.serialise_subgraph(
                subgraph,
                system_description,
                components,
            )
            try:
                assessment = yield from stage_result(re_engine.generate_assessment, subgraph_context)
            except TimeoutError:
                assessment = build_fallback_assessment(system_description, components, subgraph)
            assessment = assessment or ""

            if not assessment.strip():
                assessment = build_fallback_assessment(system_description, components, subgraph)

            timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("assessments", exist_ok=True)
            save_path = os.path.join("assessments", f"assessment_{timestamp}.json")
            saved_payload = sanitize(
                {
                    "timestamp": timestamp,
                    "system_description": system_description,
                    "components": components,
                    "search_terms": search_terms,
                    "subgraph": subgraph,
                    "assessment": assessment,
                }
            )
            with open(save_path, "w", encoding="utf-8") as handle:
                json.dump(saved_payload, handle, indent=2, ensure_ascii=False)

            yield sse_event(
                "result",
                {
                    "assessment": assessment,
                    "components": components,
                    "search_terms": search_terms,
                    "subgraph": {
                        "techniques": subgraph.get("techniques", []),
                        "mitigations": subgraph.get("mitigations", []),
                        "case_studies": subgraph.get("case_studies", []),
                        "attack_sequences": subgraph.get("attack_sequences", []),
                    },
                    "save_path": save_path,
                },
            )
            yield sse_event("done", {"message": "Assessment complete."})

        except TimeoutError as exc:
            yield sse_event("error", {"message": str(exc), "type": "timeout"})
        except Exception as exc:
            yield sse_event(
                "error",
                {
                    "message": console_safe(exc),
                    "trace": console_safe(traceback.format_exc()),
                    "type": exc.__class__.__name__,
                },
            )

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/export", methods=["POST"])
def export_report():
    from report_generator import generate_html_report

    body = request.get_json(force=True) or {}
    html = generate_html_report(
        system_description=body.get("system_description", ""),
        assessment=body.get("assessment", ""),
        components=body.get("components", []),
        search_terms=body.get("search_terms", []),
        subgraph=body.get("subgraph", {}),
    )

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ATLAS_Threat_Report_{timestamp}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def run_preflight_checks():
    print("[Startup] Checking Neo4j...")
    if not re_engine.check_neo4j():
        raise RuntimeError(
            f"Neo4j is not reachable at {re_engine.NEO4J_URI}. "
            "Start Neo4j and verify NEO4J_PASS in .env."
        )
    print("[Startup] Neo4j reachable")

    print("[Startup] Checking LLM API endpoint...")
    if not re_engine.check_api_endpoint():
        raise RuntimeError(
            f"LLM API at {re_engine.API_BASE_URL} is not reachable. "
            "Check API_BASE_URL, API_KEY, LLM_MODEL, and network access."
        )
    print("[Startup] LLM API reachable")

    print("[Startup] Loading embedding model...")
    run_stage(re_engine.get_embed_model)
    print("[Startup] Embedding model loaded")

    print("[Startup] Ensuring ATLAS technique embeddings exist...")
    run_stage(re_engine.embed_techniques_if_needed)
    print("[Startup] Embeddings ready")


if __name__ == "__main__":
    print("=" * 60)
    print("  ATLAS Reasoning Engine + Document Drafting - Web UI")
    print(f"  Version: {APP_VERSION}")
    print("=" * 60)

    try:
        run_preflight_checks()
    except RuntimeError as exc:
        print(f"Startup failed: {exc}")
        raise SystemExit(1)

    print("Ready - http://127.0.0.1:5050")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False, threaded=True)
