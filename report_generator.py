"""
report_generator.py
ATLAS Document-Drafting Application — Step 3 Optional Extension
Voyverse Technical Assessment

Generates a standalone, professional HTML threat-modelling report
with full traceable citations into the MITRE ATLAS graph.
Every claim links back to a graph node ID (AML.T*, AML.M*, AML.CS*).
"""

import re
import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CITATION RENDERER
# Converts [AML.T0051] style IDs → styled HTML badge links
# ─────────────────────────────────────────────────────────────────────────────

ATLAS_URL_BASE = "https://atlas.mitre.org"

ID_PATTERNS = {
    r"AML\.T\d{4}(?:\.\d{3})?": ("technique",   f"{ATLAS_URL_BASE}/techniques/"),
    r"AML\.M\d{4}":              ("mitigation",  f"{ATLAS_URL_BASE}/mitigations/"),
    r"AML\.CS\d{4}":             ("case-study",  f"{ATLAS_URL_BASE}/studies/"),
    r"AML\.TA\d{4}":             ("tactic",      f"{ATLAS_URL_BASE}/tactics/"),
}

def render_citations(text: str) -> str:
    """Replace [AML.X####] with styled, linked HTML badge spans."""
    def replacer(m):
        raw = m.group(0)
        inner = raw.strip("[]")
        for pattern, (css_class, base_url) in ID_PATTERNS.items():
            if re.fullmatch(pattern, inner):
                href = base_url + inner
                return (f'<a href="{href}" target="_blank" class="citation citation-{css_class}" '
                        f'title="View {inner} on MITRE ATLAS">'
                        f'<span class="citation-icon">🔗</span>{inner}</a>')
        return raw
    return re.sub(r'\[AML\.[A-Z]+\d{4}(?:\.\d{3})?\]', replacer, text)


# ─────────────────────────────────────────────────────────────────────────────
# MARKDOWN-LITE → HTML
# ─────────────────────────────────────────────────────────────────────────────

def md_to_html(text: str) -> str:
    """Convert a subset of Markdown to HTML, then render citations."""
    lines = text.split("\n")
    html_lines = []
    in_table = False
    in_list  = False
    table_header_done = False

    for line in lines:
        stripped = line.strip()

        # Tables
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("-: ") for c in cells):
                # Separator row — skip
                table_header_done = True
                continue
            if not in_table:
                in_table = True
                table_header_done = False
                html_lines.append('<div class="table-wrapper"><table class="report-table">')
            if not table_header_done:
                html_lines.append("<thead><tr>" + "".join(f"<th>{render_citations(c)}</th>" for c in cells) + "</tr></thead><tbody>")
                table_header_done = True
            else:
                # Colour-code likelihood column
                row_class = ""
                for c in cells:
                    cl = c.lower()
                    if cl == "high":    row_class = " class='risk-high'"
                    elif cl == "medium": row_class = " class='risk-medium'"
                    elif cl == "low":   row_class = " class='risk-low'"
                html_lines.append(f"<tr{row_class}>" + "".join(f"<td>{render_citations(c)}</td>" for c in cells) + "</tr>")
            continue
        elif in_table:
            html_lines.append("</tbody></table></div>")
            in_table = False
            table_header_done = False

        # Close list
        if in_list and not stripped.startswith("-") and not stripped.startswith("*"):
            html_lines.append("</ul>")
            in_list = False

        # Headings
        if stripped.startswith("### "):
            html_lines.append(f'<h3 class="report-h3">{render_citations(stripped[4:])}</h3>')
        elif stripped.startswith("## "):
            html_lines.append(f'<h2 class="report-h2">{render_citations(stripped[3:])}</h2>')
        elif stripped.startswith("# "):
            html_lines.append(f'<h1 class="report-h1">{render_citations(stripped[2:])}</h1>')
        # Horizontal rule
        elif stripped in ("---", "***", "___"):
            html_lines.append("<hr class='report-hr'>")
        # List items
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                html_lines.append("<ul class='report-list'>")
                in_list = True
            content = stripped[2:]
            # Bold inline
            content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
            html_lines.append(f"<li>{render_citations(content)}</li>")
        # Empty line → paragraph break
        elif stripped == "":
            html_lines.append("<br>")
        # Normal paragraph
        else:
            content = stripped
            content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
            content = re.sub(r'\*(.+?)\*',   r'<em>\1</em>', content)
            html_lines.append(f"<p>{render_citations(content)}</p>")

    if in_table:
        html_lines.append("</tbody></table></div>")
    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


# ─────────────────────────────────────────────────────────────────────────────
# REPORT CSS (embedded in standalone HTML)
# ─────────────────────────────────────────────────────────────────────────────

REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg:        #0d1117;
  --surface:   #161b22;
  --surface2:  #21262d;
  --border:    #30363d;
  --text:      #e6edf3;
  --text-muted:#8b949e;
  --indigo:    #6366f1;
  --teal:      #06b6d4;
  --red:       #ef4444;
  --amber:     #f59e0b;
  --green:     #22c55e;
  --pink:      #ec4899;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.7;
  padding: 0;
  margin: 0;
}

.report-wrapper {
  max-width: 960px;
  margin: 0 auto;
  padding: 48px 32px 80px;
}

/* Cover */
.report-cover {
  text-align: center;
  padding: 64px 32px 48px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 48px;
  background: linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(6,182,212,0.06) 100%);
  border-radius: 16px;
  position: relative;
  overflow: hidden;
}
.report-cover::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse at 50% 0%, rgba(99,102,241,0.15) 0%, transparent 70%);
  pointer-events: none;
}
.report-logo {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: var(--indigo);
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.report-logo::before, .report-logo::after {
  content: '';
  height: 1px;
  width: 48px;
  background: var(--indigo);
  opacity: 0.5;
}
.report-title {
  font-size: 36px;
  font-weight: 700;
  background: linear-gradient(135deg, #e6edf3 0%, var(--indigo) 60%, var(--teal) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 12px;
  line-height: 1.2;
}
.report-subtitle {
  font-size: 16px;
  color: var(--text-muted);
  margin-bottom: 32px;
}
.report-meta {
  display: flex;
  gap: 24px;
  justify-content: center;
  flex-wrap: wrap;
}
.meta-chip {
  background: rgba(255,255,255,0.04);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 6px 16px;
  font-size: 12px;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 6px;
}
.meta-chip span { color: var(--text); font-weight: 500; }

/* System description box */
.system-box {
  background: rgba(99,102,241,0.06);
  border: 1px solid rgba(99,102,241,0.2);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 48px;
}
.system-box-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--indigo);
  margin-bottom: 12px;
}
.system-box p { color: var(--text); line-height: 1.8; }

/* Stats strip */
.stats-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 48px;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}
.stat-number {
  font-size: 32px;
  font-weight: 700;
  background: linear-gradient(135deg, var(--indigo), var(--teal));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.stat-label {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-top: 4px;
}

/* Section */
.report-section {
  margin-bottom: 48px;
  padding: 32px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
}
.section-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}
.section-num {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--indigo), var(--teal));
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
  color: white;
  flex-shrink: 0;
}

/* Headings */
.report-h1 { font-size: 28px; font-weight: 700; color: var(--text); margin: 24px 0 16px; }
.report-h2 {
  font-size: 20px; font-weight: 600; color: var(--text);
  margin: 28px 0 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
.report-h3 { font-size: 16px; font-weight: 600; color: var(--teal); margin: 20px 0 8px; }
.report-hr { border: none; border-top: 1px solid var(--border); margin: 32px 0; }

/* Paragraphs & lists */
p { color: var(--text); margin-bottom: 12px; }
.report-list { padding-left: 24px; margin-bottom: 12px; }
.report-list li { margin-bottom: 8px; color: var(--text); }

/* Citation badges */
.citation {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 500;
  text-decoration: none;
  border: 1px solid;
  transition: all 0.2s;
  white-space: nowrap;
}
.citation:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
.citation-icon { font-size: 10px; }

.citation-technique  { background: rgba(99,102,241,0.15);  border-color: rgba(99,102,241,0.4);  color: #a5b4fc; }
.citation-mitigation { background: rgba(34,197,94,0.12);   border-color: rgba(34,197,94,0.35);  color: #86efac; }
.citation-case-study { background: rgba(245,158,11,0.12);  border-color: rgba(245,158,11,0.35); color: #fcd34d; }
.citation-tactic     { background: rgba(6,182,212,0.12);   border-color: rgba(6,182,212,0.35);  color: #67e8f9; }

/* Tables */
.table-wrapper { overflow-x: auto; margin: 16px 0; border-radius: 12px; border: 1px solid var(--border); }
.report-table { width: 100%; border-collapse: collapse; }
.report-table th {
  background: var(--surface2);
  padding: 12px 16px;
  text-align: left;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  text-transform: uppercase;
  border-bottom: 1px solid var(--border);
}
.report-table td {
  padding: 12px 16px;
  border-bottom: 1px solid rgba(48,54,61,0.6);
  font-size: 13px;
  vertical-align: top;
}
.report-table tr:last-child td { border-bottom: none; }
.report-table tr:hover td { background: rgba(255,255,255,0.02); }
.risk-high td:nth-child(4)   { color: var(--red);   font-weight: 600; }
.risk-medium td:nth-child(4) { color: var(--amber); font-weight: 600; }
.risk-low td:nth-child(4)    { color: var(--green); font-weight: 600; }

/* Subgraph annex */
.annex { margin-top: 64px; padding-top: 32px; border-top: 2px solid var(--border); }
.annex-title {
  font-size: 11px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; color: var(--text-muted);
  margin-bottom: 24px;
}
.annex-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.annex-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
}
.annex-card-title {
  font-size: 12px; font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 12px;
}
.node-entry {
  padding: 8px 12px;
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
}
.node-id {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--indigo);
  font-weight: 500;
}
.node-name { font-size: 13px; color: var(--text); margin-top: 2px; }
.node-desc { font-size: 12px; color: var(--text-muted); margin-top: 4px; line-height: 1.5; }

/* Attack sequences */
.seq-flow { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 6px 0; }
.seq-node {
  background: rgba(99,102,241,0.1);
  border: 1px solid rgba(99,102,241,0.3);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 12px;
  color: #a5b4fc;
}
.seq-arrow { color: var(--text-muted); font-size: 16px; }

/* Chips */
.chip-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.chip {
  background: rgba(255,255,255,0.05);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 4px 12px;
  font-size: 12px;
  color: var(--text-muted);
}

/* Footer */
.report-footer {
  text-align: center;
  margin-top: 64px;
  padding-top: 32px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--text-muted);
  line-height: 2;
}
.footer-brand { color: var(--indigo); font-weight: 600; }

@media print {
  body { background: white; color: black; }
  .report-cover { background: none; border: 2px solid #6366f1; }
  .citation { border: 1px solid #999; color: #333; background: #f5f5f5; }
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# MAIN REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(
    system_description: str,
    assessment: str,
    components: list,
    search_terms: list,
    subgraph: dict,
) -> str:
    """
    Generate a complete, standalone HTML threat-modelling report
    with embedded CSS, traceable citation links, and a graph annex.
    """

    now       = datetime.datetime.now()
    ts_human  = now.strftime("%B %d, %Y at %H:%M")
    ts_iso    = now.strftime("%Y-%m-%dT%H:%M:%S")

    techniques  = subgraph.get("techniques",  [])
    mitigations = subgraph.get("mitigations", [])
    case_studies = subgraph.get("case_studies", [])
    sequences   = subgraph.get("attack_sequences", [])

    # Render the main assessment body
    body_html = md_to_html(assessment)

    # ── Stats strip ──────────────────────────────────────────────
    stats_html = f"""
    <div class="stats-strip">
      <div class="stat-card">
        <div class="stat-number">{len(techniques)}</div>
        <div class="stat-label">Techniques</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{len(mitigations)}</div>
        <div class="stat-label">Mitigations</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{len(case_studies)}</div>
        <div class="stat-label">Case Studies</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{len(sequences)}</div>
        <div class="stat-label">Attack Paths</div>
      </div>
    </div>
    """

    # ── Components chips ─────────────────────────────────────────
    comp_chips = "".join(f'<span class="chip">{c}</span>' for c in components)
    term_chips = "".join(f'<span class="chip">{t}</span>' for t in search_terms)

    # ── Graph Annex: Techniques ───────────────────────────────────
    tech_html = ""
    for t in techniques:
        mits = ", ".join(
            f'<a href="{ATLAS_URL_BASE}/mitigations/{m["id"]}" target="_blank" '
            f'class="citation citation-mitigation">'
            f'<span class="citation-icon">🔗</span>{m["id"]}</a>'
            for m in t.get("mitigations", []) if m.get("id")
        )
        desc = (t.get("description") or "")[:200] + ("..." if len(t.get("description") or "") > 200 else "")
        tech_html += f"""
        <div class="node-entry">
          <div class="node-id">
            <a href="{ATLAS_URL_BASE}/techniques/{t['technique_id']}" target="_blank"
               class="citation citation-technique">
               <span class="citation-icon">🔗</span>{t['technique_id']}</a>
            &nbsp;—&nbsp; Tactic: {t.get('tactic','')}
          </div>
          <div class="node-name">{t.get('technique','')}</div>
          {f'<div class="node-desc">{desc}</div>' if desc else ''}
          {f'<div class="node-desc" style="margin-top:6px">Mitigations: {mits}</div>' if mits else ''}
        </div>"""

    # ── Graph Annex: Mitigations ──────────────────────────────────
    mit_html = ""
    for m in mitigations:
        desc = (m.get("desc") or "")[:160] + ("..." if len(m.get("desc") or "") > 160 else "")
        mit_html += f"""
        <div class="node-entry">
          <div class="node-id">
            <a href="{ATLAS_URL_BASE}/mitigations/{m.get('id','')}" target="_blank"
               class="citation citation-mitigation">
               <span class="citation-icon">🔗</span>{m.get('id','')}</a>
            {f'&nbsp;—&nbsp;{m.get("cat","")}' if m.get('cat') else ''}
          </div>
          <div class="node-name">{m.get('name','')}</div>
          {f'<div class="node-desc">{desc}</div>' if desc else ''}
        </div>"""

    # ── Graph Annex: Case Studies ─────────────────────────────────
    cs_html = ""
    for cs in case_studies:
        summary = (cs.get("summary") or "")[:180] + ("..." if len(cs.get("summary") or "") > 180 else "")
        cs_html += f"""
        <div class="node-entry">
          <div class="node-id">
            <a href="{ATLAS_URL_BASE}/studies/{cs.get('case_id','')}" target="_blank"
               class="citation citation-case-study">
               <span class="citation-icon">🔗</span>{cs.get('case_id','')}</a>
          </div>
          <div class="node-name">{cs.get('case_name','')}</div>
          <div class="node-desc">Technique: {cs.get('technique_used','')}</div>
          {f'<div class="node-desc">{summary}</div>' if summary else ''}
        </div>"""

    # ── Attack Sequences ─────────────────────────────────────────
    seq_html = ""
    if sequences:
        for seq in sequences:
            seq_html += f"""
            <div class="seq-flow">
              <span class="seq-node">{seq.get('from_technique','')}</span>
              <span class="seq-arrow">→</span>
              <span class="seq-node">{seq.get('to_technique','')}</span>
            </div>"""
    else:
        seq_html = '<p style="color:var(--text-muted);font-size:13px">No attack sequences retrieved.</p>'

    # ── Assemble full document ────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="MITRE ATLAS Threat Assessment Report — GraphRAG-grounded, traceable citations">
  <title>ATLAS Threat Assessment Report — {ts_iso[:10]}</title>
  <style>{REPORT_CSS}</style>
</head>
<body>
<div class="report-wrapper">

  <!-- COVER -->
  <div class="report-cover">
    <div class="report-logo">MITRE ATLAS · THREAT ASSESSMENT</div>
    <h1 class="report-title">AI Security Threat Report</h1>
    <p class="report-subtitle">GraphRAG-Grounded Analysis · Citations Traceable to MITRE ATLAS Graph Nodes</p>
    <div class="report-meta">
      <div class="meta-chip">📅 Generated: <span>{ts_human}</span></div>
      <div class="meta-chip">🔬 Source: <span>MITRE ATLAS Knowledge Graph</span></div>
      <div class="meta-chip">⚙️ Engine: <span>GraphRAG Pipeline</span></div>
      <div class="meta-chip">📊 Techniques: <span>{len(techniques)}</span></div>
    </div>
  </div>

  <!-- SYSTEM DESCRIPTION -->
  <div class="system-box">
    <div class="system-box-label">🖥 System Under Assessment</div>
    <p>{system_description}</p>
  </div>

  <!-- STATS -->
  {stats_html}

  <!-- COMPONENTS + SEARCH TERMS -->
  <div class="report-section" style="margin-bottom:32px;">
    <div class="section-header">
      <div class="section-num">🔍</div>
      <div>
        <div style="font-weight:600;font-size:15px">Query Enhancement — Identified Components &amp; ATLAS Search Terms</div>
        <div style="font-size:12px;color:var(--text-muted)">LLM-decomposed system components and ATLAS vocabulary expansion</div>
      </div>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin-bottom:8px">SYSTEM COMPONENTS</p>
    <div class="chip-row">{comp_chips if comp_chips else '<span class="chip">—</span>'}</div>
    <p style="font-size:12px;color:var(--text-muted);margin-top:16px;margin-bottom:8px">ATLAS SEARCH TERMS</p>
    <div class="chip-row">{term_chips if term_chips else '<span class="chip">—</span>'}</div>
  </div>

  <!-- ASSESSMENT BODY -->
  <div class="report-section">
    <div class="section-header">
      <div class="section-num">📋</div>
      <div>
        <div style="font-weight:600;font-size:15px">Threat Assessment Report</div>
        <div style="font-size:12px;color:var(--text-muted)">All claims grounded in the ATLAS knowledge graph. Click any citation badge to view the source node.</div>
      </div>
    </div>
    {body_html}
  </div>

  <!-- ANNEX -->
  <div class="annex">
    <div class="annex-title">📎 Appendix — Retrieved Graph Nodes</div>
    <div class="annex-grid">
      <div>
        <div class="annex-card">
          <div class="annex-card-title">⚔ Techniques ({len(techniques)})</div>
          {tech_html if tech_html else '<p style="color:var(--text-muted);font-size:13px">None retrieved.</p>'}
        </div>
      </div>
      <div>
        <div class="annex-card">
          <div class="annex-card-title">🛡 Mitigations ({len(mitigations)})</div>
          {mit_html if mit_html else '<p style="color:var(--text-muted);font-size:13px">None retrieved.</p>'}
        </div>
        <div class="annex-card" style="margin-top:16px">
          <div class="annex-card-title">📰 Case Studies ({len(case_studies)})</div>
          {cs_html if cs_html else '<p style="color:var(--text-muted);font-size:13px">None retrieved.</p>'}
        </div>
        <div class="annex-card" style="margin-top:16px">
          <div class="annex-card-title">⛓ Attack Sequences ({len(sequences)})</div>
          {seq_html}
        </div>
      </div>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="report-footer">
    <div>Generated by <span class="footer-brand">ATLAS Reasoning Engine</span> · Voyverse Technical Assessment</div>
    <div>Data source: <a href="https://atlas.mitre.org" target="_blank" style="color:var(--indigo)">MITRE ATLAS</a> · GraphRAG Pipeline (arXiv:2408.08921)</div>
    <div style="margin-top:8px;opacity:0.5">{ts_human}</div>
  </div>

</div>
</body>
</html>"""

    return html
