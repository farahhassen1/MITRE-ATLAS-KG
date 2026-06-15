// ═══════════════════════════════════════════════════════════════
// MITRE ATLAS Knowledge Graph — Example Queries
// Storage: Neo4j  |  Schema: Tactic, Technique, SubTechnique,
//          Mitigation, CaseStudy, Platform
// ═══════════════════════════════════════════════════════════════


// ── Q1 ─────────────────────────────────────────────────────────
// Which techniques appear most in real-world attack case studies?
// Use: identify the most operationally exploited techniques.
// ───────────────────────────────────────────────────────────────
MATCH (c:CaseStudy)-[:EMPLOYS]->(te)
WHERE te:Technique OR te:SubTechnique
RETURN te.id            AS technique_id,
       te.name          AS technique_name,
       te.maturity      AS maturity,
       count(c)         AS nb_case_studies
ORDER BY nb_case_studies DESC
LIMIT 10;


// ── Q2 ─────────────────────────────────────────────────────────
// Full threat path: Tactic → Technique → Mitigation
// Use: give an auditor a complete view of the attack-defence chain.
// ───────────────────────────────────────────────────────────────
MATCH (ta:Tactic)<-[:BELONGS_TO]-(te)-[:MITIGATED_BY]->(m:Mitigation)
WHERE te:Technique OR te:SubTechnique
RETURN ta.name  AS tactic,
       te.id    AS technique_id,
       te.name  AS technique,
       m.id     AS mitigation_id,
       m.name   AS mitigation,
       m.category AS mitigation_category
ORDER BY ta.name, te.id
LIMIT 25;


// ── Q3 ─────────────────────────────────────────────────────────
// Which techniques have NO mitigation documented?
// Use: flag blind spots in the current ATLAS defensive coverage.
// ───────────────────────────────────────────────────────────────
MATCH (te)
WHERE (te:Technique OR te:SubTechnique)
  AND NOT (te)-[:MITIGATED_BY]->(:Mitigation)
RETURN te.id       AS technique_id,
       te.name     AS technique_name,
       te.maturity AS maturity
ORDER BY te.id;


// ── Q4 ─────────────────────────────────────────────────────────
// Which tactic is most targeted across all real-world incidents?
// Use: prioritise defensive effort by most attacked phase.
// ───────────────────────────────────────────────────────────────
MATCH (c:CaseStudy)-[:EMPLOYS]->(te)-[:BELONGS_TO]->(ta:Tactic)
WHERE te:Technique OR te:SubTechnique
RETURN ta.id                    AS tactic_id,
       ta.name                  AS tactic_name,
       count(DISTINCT c)        AS nb_attacks,
       count(DISTINCT te)       AS nb_techniques_used
ORDER BY nb_attacks DESC;


// ── Q5 ─────────────────────────────────────────────────────────
// Voyverse's exact question:
// Which techniques target the inference path of a RAG-based
// assistant, and which mitigations exist for them?
// Use: directly answer a security engineer's audit question.
// ───────────────────────────────────────────────────────────────
MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
WHERE (te:Technique OR te:SubTechnique)
  AND (
       toLower(te.description) CONTAINS "rag"
    OR toLower(te.description) CONTAINS "retrieval"
    OR toLower(te.description) CONTAINS "inference"
    OR toLower(te.description) CONTAINS "language model"
  )
OPTIONAL MATCH (te)-[:MITIGATED_BY]->(m:Mitigation)
RETURN ta.name          AS tactic,
       te.id            AS technique_id,
       te.name          AS technique,
       collect(m.name)  AS mitigations
ORDER BY ta.name, te.id;