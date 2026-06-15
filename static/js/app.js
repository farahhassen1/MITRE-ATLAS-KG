/**
 * app.js
 * ATLAS Reasoning Engine — Frontend
 * SSE consumer · Markdown renderer · Citation highlighter · Export handler
 */

// ── STATE ─────────────────────────────────────────────────────────────────
let currentResult = null; // Holds the last completed assessment

// ── DOM REFS ──────────────────────────────────────────────────────────────
const textarea       = document.getElementById("system-input");
const charCounter    = document.getElementById("char-counter");
const btnAnalyze     = document.getElementById("btn-analyze");
const btnDemo        = document.getElementById("btn-demo");
const btnCopy        = document.getElementById("btn-copy");
const btnExport      = document.getElementById("btn-export");
const btnNew         = document.getElementById("btn-new");
const btnSpinner     = document.getElementById("btn-spinner");
const btnLabel       = document.querySelector(".btn-label");
const btnIcon        = document.querySelector(".btn-icon");

const sectionHero     = document.getElementById("section-hero");
const sectionPipeline = document.getElementById("section-pipeline");
const sectionResults  = document.getElementById("section-results");

const stage1Card = document.getElementById("stage-1");
const stage2Card = document.getElementById("stage-2");
const stage3Card = document.getElementById("stage-3");

const toast        = document.getElementById("toast");
const toastMsg     = document.getElementById("toast-message");
const toastClose   = document.getElementById("toast-close");

// ── BACKGROUND CANVAS ─────────────────────────────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById("bg-canvas");
  const ctx    = canvas.getContext("2d");
  let W, H, particles = [];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function mkParticle() {
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      r: Math.random() * 1.5 + 0.3,
      vx: (Math.random() - 0.5) * 0.18,
      vy: (Math.random() - 0.5) * 0.18,
      alpha: Math.random() * 0.5 + 0.1,
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: 120 }, mkParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d  = Math.sqrt(dx * dx + dy * dy);
        if (d < 120) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(99,102,241,${(1 - d / 120) * 0.08})`;
          ctx.lineWidth = 0.6;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw nodes
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(99,102,241,${p.alpha})`;
      ctx.fill();

      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
    });

    requestAnimationFrame(draw);
  }

  window.addEventListener("resize", resize);
  init();
  draw();
})();

// ── HEALTH CHECK ──────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const res  = await fetch("/health");
    const data = await res.json();

    setHealthDot("neo4j", data.neo4j);
    setHealthDot("api",   data.llm_api);
  } catch {
    setHealthDot("neo4j", false);
    setHealthDot("api",   false);
  }
}

function setHealthDot(id, ok) {
  const dot   = document.getElementById(`${id}-dot`);
  const label = document.getElementById(`${id}-label`);
  dot.classList.remove("loading", "ok", "error");
  dot.classList.add(ok ? "ok" : "error");
  if (id === "api") label.textContent = ok ? "LLM API" : "LLM API ✕";
}

checkHealth();

// ── TEXTAREA ──────────────────────────────────────────────────────────────
textarea.addEventListener("input", () => {
  const n = textarea.value.trim().length;
  charCounter.textContent = `${n} character${n !== 1 ? "s" : ""}`;
  btnAnalyze.disabled = n < 20;
});

// ── DEMO BUTTON ───────────────────────────────────────────────────────────
btnDemo.addEventListener("click", async () => {
  btnDemo.disabled = true;
  try {
    const res  = await fetch("/demo");
    const data = await res.json();
    textarea.value = data.description;
    textarea.dispatchEvent(new Event("input"));
  } catch {
    showToast("Could not load demo description.");
  } finally {
    btnDemo.disabled = false;
  }
});

// ── ANALYZE ───────────────────────────────────────────────────────────────
btnAnalyze.addEventListener("click", () => {
  const desc = textarea.value.trim();
  if (desc.length < 20) return;
  startAnalysis(desc);
});

function startAnalysis(description) {
  // Reset UI
  currentResult = null;
  resetStage(stage1Card, "stage-1");
  resetStage(stage2Card, "stage-2");
  resetStage(stage3Card, "stage-3");

  document.getElementById("components-chips").innerHTML = "";
  document.getElementById("terms-chips").innerHTML = "";
  document.getElementById("stage-1-body").classList.add("hidden");
  document.getElementById("stage-2-body").classList.add("hidden");
  document.getElementById("stage-3-body").classList.add("hidden");

  sectionResults.classList.add("hidden");
  sectionPipeline.classList.remove("hidden");

  setBtnLoading(true);

  const evtSrc = new EventSource(`/assess?_=${Date.now()}`);
  // POST via fetch with SSE polyfill approach — use fetch + ReadableStream
  evtSrc.close();
  streamAssessment(description);
}

async function streamAssessment(description) {
  try {
    const response = await fetch("/assess", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ description }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ error: "Unknown error" }));
      showToast(err.error || "Server error");
      setBtnLoading(false);
      return;
    }

    const reader  = response.body.getReader();
    const decoder = new TextDecoder();
    let   buffer  = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop(); // keep incomplete last chunk

      for (const part of parts) {
        if (!part.trim()) continue;
        parseSSEChunk(part);
      }
    }
  } catch (err) {
    showToast(`Connection error: ${err.message}`);
    setBtnLoading(false);
  }
}

function parseSSEChunk(raw) {
  let event = "message", data = "";
  for (const line of raw.split("\n")) {
    if (line.startsWith("event: ")) event = line.slice(7).trim();
    if (line.startsWith("data: "))  data  = line.slice(6).trim();
  }
  if (!data) return;
  try {
    const payload = JSON.parse(data);
    handleEvent(event, payload);
  } catch {
    /* ignore malformed */
  }
}

// ── SSE EVENT HANDLERS ────────────────────────────────────────────────────
function handleEvent(event, payload) {
  switch (event) {
    case "stage":       onStage(payload);       break;
    case "enhancement": onEnhancement(payload); break;
    case "subgraph":    onSubgraph(payload);     break;
    case "result":      onResult(payload);       break;
    case "done":        onDone();                break;
    case "error":       onError(payload);        break;
  }
}

function onStage({ stage, label, detail }) {
  const cards = { 1: stage1Card, 2: stage2Card, 3: stage3Card };
  const card  = cards[stage];
  if (!card) return;

  // Mark previous stages done
  for (let i = 1; i < stage; i++) {
    setStageState(cards[i], "done");
  }
  setStageState(card, "active");
  card.querySelector(".stage-subtitle").textContent = detail || card.querySelector(".stage-subtitle").textContent;
}

function onEnhancement({ components, search_terms }) {
  const compEl = document.getElementById("components-chips");
  const termEl = document.getElementById("terms-chips");
  compEl.innerHTML = "";
  termEl.innerHTML = "";

  components.forEach((c, i) => {
    const chip = makeChip(c, "component");
    chip.style.animationDelay = `${i * 40}ms`;
    compEl.appendChild(chip);
  });
  search_terms.forEach((t, i) => {
    const chip = makeChip(t, "term");
    chip.style.animationDelay = `${i * 30}ms`;
    termEl.appendChild(chip);
  });

  document.getElementById("stage-1-body").classList.remove("hidden");
}

function onSubgraph({ techniques, mitigations, case_studies, attack_sequences }) {
  document.getElementById("sg-techniques").textContent = techniques;
  document.getElementById("sg-mitigations").textContent = mitigations;
  document.getElementById("sg-cases").textContent = case_studies;
  document.getElementById("sg-paths").textContent = attack_sequences;
  document.getElementById("stage-2-body").classList.remove("hidden");
  document.getElementById("stage-3-body").classList.remove("hidden");
}

function onResult({ assessment, components, search_terms, subgraph }) {
  currentResult = { assessment, components, search_terms, subgraph };

  // Populate sidebar
  document.getElementById("sbs-techniques").textContent = subgraph.techniques?.length  ?? 0;
  document.getElementById("sbs-mitigations").textContent = subgraph.mitigations?.length ?? 0;
  document.getElementById("sbs-cases").textContent      = subgraph.case_studies?.length ?? 0;
  document.getElementById("sbs-paths").textContent      = subgraph.attack_sequences?.length ?? 0;

  const compEl = document.getElementById("sidebar-components");
  compEl.innerHTML = "";
  components.forEach(c => compEl.appendChild(makeChip(c, "component")));

  // Attack sequences sidebar
  const seqEl = document.getElementById("sidebar-sequences");
  seqEl.innerHTML = "";
  const seqs = subgraph.attack_sequences || [];
  if (seqs.length === 0) {
    seqEl.innerHTML = `<p style="font-size:12px;color:var(--text-muted)">None retrieved.</p>`;
  } else {
    seqs.forEach(s => {
      const div = document.createElement("div");
      div.className = "seq-flow";
      div.innerHTML = `<span class="seq-node">${esc(s.from_technique)}</span>
                       <span class="seq-arrow">→</span>
                       <span class="seq-node">${esc(s.to_technique)}</span>`;
      seqEl.appendChild(div);
    });
  }

  // Render report
  document.getElementById("report-content").innerHTML = renderReport(assessment);
  sectionResults.classList.remove("hidden");
  sectionResults.scrollIntoView({ behavior: "smooth", block: "start" });
}

function onDone() {
  setStageState(stage1Card, "done");
  setStageState(stage2Card, "done");
  setStageState(stage3Card, "done");
  setBtnLoading(false);
}

function onError({ message }) {
  showToast(message || "An error occurred.");
  setStageState(stage1Card, "error");
  setStageState(stage2Card, "error");
  setStageState(stage3Card, "error");
  setBtnLoading(false);
}

// ── REPORT RENDERER ───────────────────────────────────────────────────────
/**
 * Convert Markdown-like assessment text to styled HTML.
 * Handles headings, bullet lists, tables, bold, and citation badges.
 */
function renderReport(markdown) {
  const lines = markdown.split("\n");
  let html = "";
  let inList  = false;
  let inTable = false;
  let tableHeaderDone = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const s   = raw.trim();

    // TABLE
    if (s.startsWith("|")) {
      const cells = s.split("|").slice(1, -1).map(c => c.trim());
      if (cells.every(c => /^[-: ]+$/.test(c))) {
        tableHeaderDone = true;
        continue; // separator row
      }
      if (!inTable) {
        if (inList) { html += "</ul>"; inList = false; }
        html += `<div class="table-wrapper"><table class="report-table">`;
        inTable = true;
        tableHeaderDone = false;
      }
      if (!tableHeaderDone) {
        html += `<thead><tr>${cells.map(c => `<th>${cite(c)}</th>`).join("")}</tr></thead><tbody>`;
        tableHeaderDone = true;
      } else {
        let rowClass = "";
        cells.forEach(c => {
          if (c.toLowerCase() === "high")   rowClass = " class='risk-high'";
          if (c.toLowerCase() === "medium") rowClass = " class='risk-medium'";
          if (c.toLowerCase() === "low")    rowClass = " class='risk-low'";
        });
        html += `<tr${rowClass}>${cells.map(c => `<td>${cite(c)}</td>`).join("")}</tr>`;
      }
      continue;
    } else if (inTable) {
      html += `</tbody></table></div>`;
      inTable = false;
      tableHeaderDone = false;
    }

    // CLOSE LIST
    if (inList && !s.startsWith("- ") && !s.startsWith("* ")) {
      html += "</ul>";
      inList = false;
    }

    if (s.startsWith("## ")) {
      html += `<h2>${cite(s.slice(3))}</h2>`;
    } else if (s.startsWith("### ")) {
      html += `<h3>${cite(s.slice(4))}</h3>`;
    } else if (s.startsWith("# ")) {
      html += `<h2>${cite(s.slice(2))}</h2>`; // treat h1 as h2 inside panel
    } else if (s === "---" || s === "***") {
      html += `<hr>`;
    } else if (s.startsWith("- ") || s.startsWith("* ")) {
      if (!inList) { html += `<ul>`; inList = true; }
      const content = bold(cite(s.slice(2)));
      html += `<li>${content}</li>`;
    } else if (s === "") {
      html += ``;
    } else {
      html += `<p>${bold(cite(s))}</p>`;
    }
  }

  if (inList)  html += "</ul>";
  if (inTable) html += "</tbody></table></div>";

  return html;
}

/** Replace **text** with <strong> */
function bold(text) {
  return text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
             .replace(/\*(.+?)\*/g, "<em>$1</em>");
}

/** Replace [AML.X####] with styled citation badges */
function cite(text) {
  return text.replace(/\[AML\.[A-Z]+\d{4}(?:\.\d{3})?\]/g, match => {
    const id   = match.slice(1, -1);
    const type = getCitationType(id);
    const url  = getCiteURL(id);
    return `<a href="${url}" target="_blank" class="citation citation-${type}" title="View ${id} on MITRE ATLAS">
              <span class="citation-icon">🔗</span>${id}</a>`;
  });
}

function getCitationType(id) {
  if (id.startsWith("AML.T"))  return "technique";
  if (id.startsWith("AML.M"))  return "mitigation";
  if (id.startsWith("AML.CS")) return "case-study";
  if (id.startsWith("AML.TA")) return "tactic";
  return "technique";
}

function getCiteURL(id) {
  const base = "https://atlas.mitre.org";
  if (id.startsWith("AML.T"))  return `${base}/techniques/${id}`;
  if (id.startsWith("AML.M"))  return `${base}/mitigations/${id}`;
  if (id.startsWith("AML.CS")) return `${base}/studies/${id}`;
  if (id.startsWith("AML.TA")) return `${base}/tactics/${id}`;
  return base;
}

// ── EXPORT ────────────────────────────────────────────────────────────────
btnExport.addEventListener("click", async () => {
  if (!currentResult) return;
  btnExport.disabled = true;
  btnExport.textContent = "Generating…";

  try {
    const res = await fetch("/export", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        assessment:         currentResult.assessment,
        components:         currentResult.components,
        search_terms:       currentResult.search_terms,
        subgraph:           currentResult.subgraph,
        system_description: textarea.value.trim(),
      }),
    });

    if (!res.ok) {
      showToast("Export failed. Check server logs.");
      return;
    }

    const blob     = await res.blob();
    const url      = URL.createObjectURL(blob);
    const a        = document.createElement("a");
    const filename = res.headers.get("content-disposition")?.match(/filename="(.+)"/)?.[1]
                     || `ATLAS_Threat_Report.html`;
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    showToast(`Export error: ${err.message}`);
  } finally {
    btnExport.disabled = false;
    btnExport.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Export Report`;
  }
});

// ── COPY ──────────────────────────────────────────────────────────────────
btnCopy.addEventListener("click", async () => {
  if (!currentResult) return;
  try {
    await navigator.clipboard.writeText(currentResult.assessment);
    btnCopy.textContent = "✓ Copied!";
    setTimeout(() => {
      btnCopy.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg> Copy`;
    }, 2000);
  } catch {
    showToast("Clipboard not available. Use HTTPS or localhost.");
  }
});

// ── NEW ASSESSMENT ────────────────────────────────────────────────────────
btnNew.addEventListener("click", () => {
  sectionResults.classList.add("hidden");
  sectionPipeline.classList.add("hidden");
  textarea.value = "";
  textarea.dispatchEvent(new Event("input"));
  sectionHero.scrollIntoView({ behavior: "smooth" });
  textarea.focus();
});

// ── TOAST ─────────────────────────────────────────────────────────────────
function showToast(msg) {
  toastMsg.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(hideToast, 8000);
}
function hideToast() { toast.classList.add("hidden"); }
toastClose.addEventListener("click", hideToast);

// ── HELPERS ───────────────────────────────────────────────────────────────
function setStageState(card, state) {
  card.dataset.state = state;
  const icon = card.querySelector(".stage-status-icon");
  if (icon) {
    const sp = icon.querySelector(".spinner");
    if (state === "active" && sp) sp.style.display = "block";
    if (state !== "active" && sp) sp.style.display = "none";
  }
}

function resetStage(card, id) {
  card.dataset.state = "idle";
  const body = document.getElementById(`${id}-body`);
  if (body) body.classList.add("hidden");
}

function setBtnLoading(loading) {
  if (loading) {
    btnAnalyze.classList.add("loading");
    btnSpinner.classList.remove("hidden");
    btnIcon.classList.add("hidden");
    btnLabel.textContent = "Analyzing…";
    btnAnalyze.disabled = true;
  } else {
    btnAnalyze.classList.remove("loading");
    btnSpinner.classList.add("hidden");
    btnIcon.classList.remove("hidden");
    btnLabel.textContent = "Analyze Threats";
    btnAnalyze.disabled = textarea.value.trim().length < 20;
  }
}

function makeChip(text, type = "") {
  const span = document.createElement("span");
  span.className = `chip ${type}`;
  span.textContent = text;
  return span;
}

function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
