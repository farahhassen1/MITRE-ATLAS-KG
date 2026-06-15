#run_queries.py - Execute Cypher queries against the MITRE ATLAS graph database and print results in a readable format.
from neo4j import GraphDatabase

driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "29703391")
)

queries = {
    "Q1 — Which techniques appear most in real-world attacks?": """
        MATCH (c:CaseStudy)-[:EMPLOYS]->(te)
        WHERE te:Technique OR te:SubTechnique
        RETURN te.name AS technique, count(c) AS nb_cases
        ORDER BY nb_cases DESC
        LIMIT 10
    """,

    "Q2 — Full threat path: Tactic → Technique → Mitigation": """
        MATCH (ta:Tactic)<-[:BELONGS_TO]-(te)-[:MITIGATED_BY]->(m:Mitigation)
        RETURN ta.name AS tactic, te.name AS technique, m.name AS mitigation
        ORDER BY ta.name
        LIMIT 20
    """,

    "Q3 — Which techniques have no mitigation documented?": """
        MATCH (te)
        WHERE (te:Technique OR te:SubTechnique)
          AND NOT (te)-[:MITIGATED_BY]->(:Mitigation)
        RETURN te.name AS unmitigated_technique
        ORDER BY te.name
    """,

    "Q4 — Which tactic is most targeted in real attacks?": """
        MATCH (c:CaseStudy)-[:EMPLOYS]->(te)-[:BELONGS_TO]->(ta:Tactic)
        RETURN ta.name AS tactic, count(DISTINCT c) AS nb_attacks
        ORDER BY nb_attacks DESC
    """,

    "Q5 — Techniques targeting RAG/inference + their mitigations": """
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
    """
}

with driver.session() as session:
    for title, query in queries.items():

        print("\n" + "═" * 70)
        print(f"  {title}")
        print("═" * 70)

        results = session.run(query)
        rows = results.data()

        if not rows:
            print("  (no results)")
            continue

        # print header from first row keys
        keys = list(rows[0].keys())
        col_width = 35
        header = "  " + " │ ".join(k.ljust(col_width) for k in keys)
        print(header)
        print("  " + "─" * (len(header) - 2))

        for row in rows:
            line = "  " + " │ ".join(
                str(row[k])[:col_width].ljust(col_width) for k in keys
            )
            print(line)

        print(f"\n  → {len(rows)} row(s) returned")

driver.close()
print("\n✅ All queries executed.")