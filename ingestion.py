import yaml
from pathlib import Path
from neo4j import GraphDatabase

# ── CONNECTION ───────────────────────────────────────────
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "29703391")
)

# ── LOAD FILES ───────────────────────────────────────────
path_v6     = Path("data/v6/ATLAS-2026.05.yaml")
with path_v6.open("r", encoding="utf-8") as f:
    raw = yaml.safe_load(f)

path_legacy = Path("data/legacy/ATLAS-5.6.0.yaml")
with path_legacy.open("r", encoding="utf-8") as f:
    legacy = yaml.safe_load(f)

tactics       = list(raw.get("tactics", {}).values())
techniques    = list(raw.get("techniques", {}).values())
mitigations   = list(raw.get("mitigations", {}).values())
case_studies  = list(raw.get("case-studies", {}).values())
relationships = raw.get("relationships", {})

legacy_matrix      = legacy["matrices"][0]
legacy_mitigations = legacy_matrix["mitigations"]
legacy_techniques  = legacy_matrix["techniques"]

print(f"v6     → {len(tactics)} tactics, {len(techniques)} techniques, "
      f"{len(mitigations)} mitigations, {len(case_studies)} case studies")
print(f"legacy → {len(legacy_mitigations)} mitigations with technique links")

# ── CLEAR + CONSTRAINTS ──────────────────────────────────
with driver.session() as session:
    session.run("MATCH (n) DETACH DELETE n")
    print("✅ Database cleared")

    for constraint in [
        "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tactic)       REQUIRE t.id   IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique)    REQUIRE t.id   IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (s:SubTechnique) REQUIRE s.id   IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Mitigation)   REQUIRE m.id   IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (c:CaseStudy)    REQUIRE c.id   IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Platform)     REQUIRE p.name IS UNIQUE",
    ]:
        session.run(constraint)
    print("✅ Constraints created")

# ── NODES ────────────────────────────────────────────────
def load_nodes(tx):

    # Tactics
    for t in tactics:
        tx.run("""
            MERGE (ta:Tactic {id: $id})
            SET ta.name = $name, ta.description = $desc
        """, id=t["id"], name=t["name"],
             desc=(t.get("description") or "").strip())

    # Techniques vs SubTechniques
    platforms = set()
    top_level = []
    sub_level = []

    for t in techniques:
        tid = t["id"]
        parts = tid.split(".")
        is_sub = len(parts) == 3  # AML.T0000.000 = sub

        plats = t.get("platforms", []) or []
        platforms.update(plats)

        row = {
            "id": tid,
            "name": t.get("name"),
            "desc": (t.get("description") or "").strip(),
            "maturity": t.get("maturity", ""),
            "platforms": plats,
        }
        if is_sub:
            sub_level.append(row)
        else:
            top_level.append(row)

    # Platform nodes
    for p in platforms:
        tx.run("MERGE (:Platform {name: $name})", name=p)

    # Technique nodes
    for t in top_level:
        tx.run("""
            MERGE (te:Technique {id: $id})
            SET te.name = $name,
                te.description = $desc,
                te.maturity = $maturity,
                te.platforms = $platforms
        """, **t)
        for p in t["platforms"]:
            tx.run("""
                MATCH (te:Technique {id: $tid})
                MATCH (p:Platform   {name: $pname})
                MERGE (te)-[:TARGETS]->(p)
            """, tid=t["id"], pname=p)

    # SubTechnique nodes
    for t in sub_level:
        tx.run("""
            MERGE (s:SubTechnique {id: $id})
            SET s.name = $name,
                s.description = $desc,
                s.maturity = $maturity,
                s.platforms = $platforms
        """, **t)
        for p in t["platforms"]:
            tx.run("""
                MATCH (s:SubTechnique {id: $tid})
                MATCH (p:Platform     {name: $pname})
                MERGE (s)-[:TARGETS]->(p)
            """, tid=t["id"], pname=p)

    # Mitigations with category + lifecycle
        for m in legacy_mitigations:
            raw_cat = m.get("categories") or m.get("category")
            category = ", ".join(raw_cat) if isinstance(raw_cat, list) else (raw_cat or "")
            
            lifecycle_raw = m.get("ml-lifecycle") or m.get("lifecycle-phases") or []
            # convert any dict items to strings
            lifecycle = [
                v if isinstance(v, str) else str(v)
                for v in lifecycle_raw
            ]
            lifecycle_str = ", ".join(lifecycle)  # store as plain string

            tx.run("""
                MERGE (mi:Mitigation {id: $id})
                SET mi.name            = $name,
                    mi.description     = $desc,
                    mi.category        = $category,
                    mi.lifecycle_phases = $lifecycle
            """, id=m["id"], name=m["name"],
                desc=(m.get("description") or "").strip(),
                category=category,
                lifecycle=lifecycle_str)

    # Case Studies
    for cs in case_studies:
        tx.run("""
            MERGE (c:CaseStudy {id: $id})
            SET c.name = $name, c.summary = $summary
        """, id=cs["id"], name=cs["name"],
             summary=(cs.get("summary") or "").strip())

with driver.session() as session:
    session.execute_write(load_nodes)
    print("✅ Nodes loaded")

# ── RELATIONSHIPS ────────────────────────────────────────
def load_relationships_fn(tx):

    # 1. BELONGS_TO: Technique/SubTechnique → Tactic (from legacy)
    for t in legacy_techniques:
        for tac_id in t.get("tactics", []):
            tac_id = tac_id["id"] if isinstance(tac_id, dict) else tac_id
            tx.run("""
                MATCH (te {id: $tech_id})
                WHERE te:Technique OR te:SubTechnique
                MATCH (ta:Tactic {id: $tac_id})
                MERGE (te)-[:BELONGS_TO]->(ta)
            """, tech_id=t["id"], tac_id=tac_id)

    # 2. SUBTECHNIQUE_OF: SubTechnique → Technique
    for t in techniques:
        tid = t["id"]
        parts = tid.split(".")
        if len(parts) == 3:
            parent_id = f"{parts[0]}.{parts[1]}"
            tx.run("""
                MATCH (s:SubTechnique {id: $sub_id})
                MATCH (te:Technique   {id: $parent_id})
                MERGE (s)-[:SUBTECHNIQUE_OF]->(te)
            """, sub_id=tid, parent_id=parent_id)

    # 3. MITIGATED_BY: Technique/SubTechnique → Mitigation (from legacy)
    for mit in legacy_mitigations:
        for tech in mit.get("techniques", []):
            tech_id = tech["id"] if isinstance(tech, dict) else tech
            use     = tech.get("use", "") if isinstance(tech, dict) else ""
            tx.run("""
                MATCH (te {id: $tech_id})
                WHERE te:Technique OR te:SubTechnique
                MATCH (mi:Mitigation {id: $mit_id})
                MERGE (te)-[:MITIGATED_BY {use: $use}]->(mi)
            """, tech_id=tech_id, mit_id=mit["id"], use=use)

    # 4. EMPLOYS: CaseStudy → Technique/SubTechnique (from v6)
    for source_id, rel_block in relationships.items():
        if not isinstance(rel_block, dict):
            continue
        for rel in rel_block.get("employs", []):
            tx.run("""
                MATCH (c:CaseStudy {id: $cs_id})
                MATCH (te {id: $tech_id})
                WHERE te:Technique OR te:SubTechnique
                MERGE (c)-[:EMPLOYS {
                    procedure: $procedure,
                    tactic_id: $tactic_id
                }]->(te)
            """, cs_id=source_id,
                 tech_id=rel["target"],
                 procedure=(rel.get("description") or "").strip(),
                 tactic_id=rel.get("tactic", ""))

    # 5. FOLLOWED_BY: Technique → Technique (attack sequence chains)
    pairs = set()
    for key, val in relationships.items():
        if not key.startswith("AML.CS"):
            continue
        employs = val.get("employs", []) or []
        step_to_tech = {
            e["step-id"]: e["target"]
            for e in employs
            if e.get("step-id") and e.get("target")
        }
        for e in employs:
            from_tech = e.get("target")
            for next_step in e.get("leads-to", []) or []:
                to_tech = step_to_tech.get(next_step)
                if to_tech and from_tech != to_tech:
                    pairs.add((from_tech, to_tech))

    for from_id, to_id in pairs:
        tx.run("""
            MATCH (a {id: $from_id})
            MATCH (b {id: $to_id})
            WHERE (a:Technique OR a:SubTechnique)
              AND (b:Technique OR b:SubTechnique)
            MERGE (a)-[:FOLLOWED_BY]->(b)
        """, from_id=from_id, to_id=to_id)

with driver.session() as session:
    session.execute_write(load_relationships_fn)
    print("✅ Relationships loaded")

# ── VERIFY ───────────────────────────────────────────────
with driver.session() as session:
    print("\n=== Node counts ===")
    result = session.run(
        "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
    )
    for row in result:
        print(f"  {row['label']}: {row['count']}")

    print("\n=== Relationship counts ===")
    result = session.run(
        "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC"
    )
    for row in result:
        print(f"  {row['type']}: {row['count']}")

driver.close()
print("\n✅ Graph ready")