# eval/coverage.py
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "29703391"))

with driver.session() as session:

    result = session.run("""
        MATCH (te)
        WHERE te:Technique OR te:SubTechnique
        OPTIONAL MATCH (te)-[:MITIGATED_BY]->(m:Mitigation)
        RETURN
            count(DISTINCT te) AS total,
            count(DISTINCT CASE WHEN m IS NOT NULL THEN te END) AS with_mitigation
    """)
    row = result.single()
    total = row["total"]
    covered = row["with_mitigation"]
    print(f"Mitigation coverage: {covered}/{total} = {covered/total*100:.1f}%")

    result = session.run("""
        MATCH (te)
        WHERE te:Technique OR te:SubTechnique
        OPTIONAL MATCH (cs:CaseStudy)-[:EMPLOYS]->(te)
        RETURN
            count(DISTINCT te) AS total,
            count(DISTINCT CASE WHEN cs IS NOT NULL THEN te END) AS in_case_study
    """)
    row = result.single()
    total = row["total"]
    in_cs = row["in_case_study"]
    print(f"Case study coverage: {in_cs}/{total} = {in_cs/total*100:.1f}%")

    result = session.run("""
        MATCH (te)
        WHERE te:Technique OR te:SubTechnique
        OPTIONAL MATCH (te)-[:BELONGS_TO]->(ta:Tactic)
        RETURN
            count(DISTINCT te) AS total,
            count(DISTINCT CASE WHEN ta IS NOT NULL THEN te END) AS with_tactic
    """)
    row = result.single()
    total = row["total"]
    with_tac = row["with_tactic"]
    print(f"Tactic coverage:    {with_tac}/{total} = {with_tac/total*100:.1f}%")

    result = session.run("""
        MATCH (te)
        WHERE te:Technique OR te:SubTechnique
        OPTIONAL MATCH (te)-[:MITIGATED_BY]->(m:Mitigation)
        WITH te, count(m) AS nb_mit
        RETURN avg(nb_mit) AS avg_mitigations
    """)
    avg = result.single()["avg_mitigations"]
    print(f"Avg mitigations per technique: {avg:.2f}")

driver.close()