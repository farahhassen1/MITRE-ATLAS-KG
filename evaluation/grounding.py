# eval/grounding.py
import re
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "29703391"))

# Paste your generated assessment here
assessment = """
[AML.T0051] LLM Prompt Injection ... [AML.M0015] ...
[AML.T0070] RAG Poisoning ... [AML.CS0055] ...
"""

# Extract all cited IDs from the report
cited_ids = set(re.findall(r'AML\.[A-Z]+\d{4}(?:\.\d{3})?', assessment))
print(f"Cited IDs in report: {cited_ids}")

# Check each against the graph
with driver.session() as session:
    grounded = set()
    hallucinated = set()
    for atlas_id in cited_ids:
        result = session.run(
            "MATCH (n {id: $id}) RETURN n LIMIT 1",
            id=atlas_id
        )
        if result.single():
            grounded.add(atlas_id)
        else:
            hallucinated.add(atlas_id)

grounding_rate = len(grounded) / len(cited_ids) * 100 if cited_ids else 0

print(f"\nGrounded IDs (exist in graph): {grounded}")
print(f"Hallucinated IDs (not in graph): {hallucinated}")
print(f"\nGrounding rate: {len(grounded)}/{len(cited_ids)} = {grounding_rate:.1f}%")

driver.close()