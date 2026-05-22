"""
threat_api/main.py
==================
Robert Consulting Threat Intelligence API

Exposes MITRE ATT&CK Enterprise data, CISA KEV catalog, and
cross-references to compliance framework controls via the
compliance API.

Endpoints:
    GET /health                          — liveness probe
    GET /stats                           — summary counts

    GET /tactics                         — list all ATT&CK tactics
    GET /tactics/{tactic_id}             — tactic detail with techniques

    GET /heatmap/data                    — tactics + techniques + counts for heatmap UI

    GET /techniques                      — list techniques (paginated, filterable)
    GET /techniques/{technique_id}       — technique detail
    GET /techniques/{technique_id}/groups  — groups using this technique
    GET /techniques/{technique_id}/software — software implementing this technique
    GET /techniques/{technique_id}/compliance — compliance controls (via compliance API)

    GET /groups                          — list threat actor groups (filterable by metadata)
    GET /groups/{group_id}               — group detail with techniques used
    GET /groups/{group_id}/techniques    — techniques used by this group
    GET /groups/{group_id}/software      — software used by this group

    GET /stats/by-country                — group and technique counts by country

    GET /software                        — list malware and tools
    GET /software/{software_id}          — software detail with techniques

    GET /kev                             — CISA KEV entries (paginated, filterable)
    GET /kev/{cve_id}                    — single KEV entry
    GET /kev/stats                       — KEV summary statistics

    GET /search                          — search across techniques, groups, software
"""

import json
import os
import sqlite3
import logging
import httpx
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# =============================================================================
# Configuration
# =============================================================================

DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/threat.db")
COMPLIANCE_API_URL = os.getenv(
    "COMPLIANCE_API_URL",
    "https://api.compliance.robertconsulting.net"
)
LOG_LEVEL = os.getenv("LOG_LEVEL", "info").upper()
CORS_ORIGINS_RAW = os.getenv(
    "CORS_ORIGINS",
    "https://threat.robertconsulting.net,https://robertconsulting.net"
)
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",")]

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
log = logging.getLogger(__name__)

# =============================================================================
# Database helpers
# =============================================================================

def get_db() -> sqlite3.Connection:
    if not os.path.exists(DATABASE_PATH):
        raise RuntimeError(f"Database not found at {DATABASE_PATH}")
    conn = sqlite3.connect(
        f"file:{DATABASE_PATH}?mode=ro&immutable=1", uri=True, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    return conn


def query(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# =============================================================================
# App lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(f"Starting Threat API — database: {DATABASE_PATH}")
    try:
        result = query_one("SELECT COUNT(*) as n FROM techniques WHERE is_deprecated=0")
        log.info(f"Database ready — {result['n']} active techniques")
    except Exception as e:
        log.error(f"Database check failed: {e}")
        raise
    yield
    log.info("Threat API shutting down")

# =============================================================================
# FastAPI app
# =============================================================================

app = FastAPI(
    title="Robert Consulting Threat Intelligence API",
    description=(
        "MITRE ATT&CK Enterprise threat intelligence with CISA KEV data "
        "and cross-references to compliance framework controls. "
        "Covers 467 techniques, 174 groups, 821 software, and 1,200+ KEV entries."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# =============================================================================
# Health & Stats
# =============================================================================

@app.get("/health", tags=["system"])
def health():
    try:
        result = query_one(
            "SELECT COUNT(*) as n FROM techniques WHERE is_deprecated=0 AND is_revoked=0"
        )
        return {"status": "ok", "database": DATABASE_PATH, "active_techniques": result["n"]}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/stats", tags=["system"])
def stats():
    try:
        techniques = query_one(
            "SELECT COUNT(*) as n FROM techniques WHERE is_deprecated=0 AND is_revoked=0"
        )["n"]
        subtechniques = query_one(
            "SELECT COUNT(*) as n FROM techniques WHERE is_subtechnique=1 AND is_deprecated=0"
        )["n"]
        tactics = query_one("SELECT COUNT(*) as n FROM tactics")["n"]
        groups = query_one("SELECT COUNT(*) as n FROM groups")["n"]
        software = query_one("SELECT COUNT(*) as n FROM software")["n"]
        kev = query_one("SELECT COUNT(*) as n FROM kev_entries")["n"]
        kev_ransomware = query_one(
            "SELECT COUNT(*) as n FROM kev_entries WHERE known_ransomware='Known'"
        )["n"]
        group_technique_links = query_one(
            "SELECT COUNT(*) as n FROM group_techniques"
        )["n"]

        meta = query("SELECT source, version, imported_at FROM import_metadata")

        return {
            "techniques": techniques,
            "sub_techniques": subtechniques,
            "tactics": tactics,
            "groups": groups,
            "software": software,
            "kev_entries": kev,
            "kev_ransomware_associated": kev_ransomware,
            "group_technique_relationships": group_technique_links,
            "data_sources": meta,
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/stats/by-country", tags=["system"])
def stats_by_country():
    """Group and technique counts broken down by attributed country."""
    rows = query("""
        SELECT gm.country, gm.country_name, gm.sponsor_type,
               COUNT(DISTINCT g.group_id) as group_count,
               COUNT(DISTINCT gt.technique_id) as technique_count
        FROM group_metadata gm
        JOIN groups g ON gm.group_id = g.group_id
        LEFT JOIN group_techniques gt ON g.group_id = gt.group_id
        WHERE gm.country IS NOT NULL AND gm.country != 'ZZ'
        GROUP BY gm.country, gm.country_name, gm.sponsor_type
        ORDER BY group_count DESC
    """)
    return {"by_country": rows}

# =============================================================================
# Tactics
# =============================================================================

@app.get("/tactics", tags=["tactics"])
def list_tactics():
    return query("""
        SELECT t.tactic_id, t.name, t.description, t.url,
               COUNT(DISTINCT tt.technique_id) as technique_count
        FROM tactics t
        LEFT JOIN technique_tactics tt ON t.tactic_id = tt.tactic_id
        LEFT JOIN techniques tech ON tt.technique_id = tech.technique_id
            AND tech.is_deprecated = 0 AND tech.is_revoked = 0
        GROUP BY t.tactic_id
        ORDER BY t.tactic_id
    """)


@app.get("/heatmap/data", tags=["heatmap"])
def heatmap_data():
    """
    Returns all data needed to render the ATT&CK Navigator-style heatmap
    in a single request. Includes every non-deprecated base technique and
    sub-technique with tactic assignments, group usage count, and KEV count.
    """
    tactics = query(
        "SELECT tactic_id, name FROM tactics ORDER BY tactic_id"
    )

    techniques = query("""
        SELECT
            t.technique_id,
            t.name,
            t.is_subtechnique,
            t.parent_technique_id,
            t.platforms,
            COUNT(DISTINCT gt.group_id)  AS group_count,
            COUNT(DISTINCT ktm.cve_id)   AS kev_count
        FROM techniques t
        LEFT JOIN group_techniques gt  ON t.technique_id = gt.technique_id
        LEFT JOIN kev_technique_mappings ktm ON t.technique_id = ktm.technique_id
        WHERE t.is_deprecated = 0 AND t.is_revoked = 0
        GROUP BY t.technique_id
        ORDER BY t.technique_id
    """)

    assignments = query("""
        SELECT tt.tactic_id, tt.technique_id
        FROM technique_tactics tt
        JOIN techniques t ON tt.technique_id = t.technique_id
        WHERE t.is_deprecated = 0 AND t.is_revoked = 0
    """)

    tactic_map = {t["tactic_id"]: [] for t in tactics}
    for a in assignments:
        if a["tactic_id"] in tactic_map:
            tactic_map[a["tactic_id"]].append(a["technique_id"])

    for tactic in tactics:
        tactic["technique_count"] = len(tactic_map[tactic["tactic_id"]])

    return {
        "tactics": tactics,
        "techniques": techniques,
        "tactic_techniques": tactic_map,
    }


@app.get("/tactics/{tactic_id}", tags=["tactics"])
def get_tactic(tactic_id: str):
    tactic = query_one(
        "SELECT * FROM tactics WHERE tactic_id = ?", (tactic_id.upper(),)
    )
    if not tactic:
        raise HTTPException(status_code=404, detail=f"Tactic '{tactic_id}' not found")

    techniques = query("""
        SELECT t.technique_id, t.name, t.is_subtechnique, t.parent_technique_id,
               t.platforms
        FROM techniques t
        JOIN technique_tactics tt ON t.technique_id = tt.technique_id
        WHERE tt.tactic_id = ? AND t.is_deprecated = 0 AND t.is_revoked = 0
        ORDER BY t.technique_id
    """, (tactic_id.upper(),))

    return {**tactic, "technique_count": len(techniques), "techniques": techniques}

# =============================================================================
# Techniques
# =============================================================================

@app.get("/techniques", tags=["techniques"])
def list_techniques(
    tactic: Optional[str] = Query(default=None, description="Filter by tactic ID e.g. TA0001"),
    platform: Optional[str] = Query(default=None, description="Filter by platform e.g. Windows"),
    subtechniques: bool = Query(default=True, description="Include sub-techniques"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
):
    where = ["t.is_deprecated = 0", "t.is_revoked = 0"]
    params = []

    if not subtechniques:
        where.append("t.is_subtechnique = 0")

    if tactic:
        where.append("""
            t.technique_id IN (
                SELECT technique_id FROM technique_tactics WHERE tactic_id = ?
            )
        """)
        params.append(tactic.upper())

    if platform:
        where.append("t.platforms LIKE ?")
        params.append(f"%{platform}%")

    where_sql = "WHERE " + " AND ".join(where)

    total = query_one(
        f"SELECT COUNT(*) as n FROM techniques t {where_sql}", tuple(params)
    )["n"]

    offset = (page - 1) * page_size
    results = query(
        f"""SELECT t.technique_id, t.name, t.is_subtechnique,
                   t.parent_technique_id, t.platforms, t.url
            FROM techniques t {where_sql}
            ORDER BY t.technique_id
            LIMIT ? OFFSET ?""",
        tuple(params) + (page_size, offset)
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "techniques": results,
    }


@app.get("/techniques/{technique_id}", tags=["techniques"])
def get_technique(technique_id: str):
    tech = query_one(
        "SELECT * FROM techniques WHERE technique_id = ?",
        (technique_id.upper(),)
    )
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")

    # Tactics
    tactics = query("""
        SELECT t.tactic_id, t.name
        FROM tactics t
        JOIN technique_tactics tt ON t.tactic_id = tt.tactic_id
        WHERE tt.technique_id = ?
    """, (technique_id.upper(),))

    # Sub-techniques (if this is a base technique)
    subs = []
    if not tech["is_subtechnique"]:
        subs = query("""
            SELECT technique_id, name, platforms
            FROM techniques
            WHERE parent_technique_id = ? AND is_deprecated = 0
            ORDER BY technique_id
        """, (technique_id.upper(),))

    # Groups using this technique (count only for the list view)
    group_count = query_one(
        "SELECT COUNT(*) as n FROM group_techniques WHERE technique_id = ?",
        (technique_id.upper(),)
    )["n"]

    # Software implementing this technique (count only)
    sw_count = query_one(
        "SELECT COUNT(*) as n FROM software_techniques WHERE technique_id = ?",
        (technique_id.upper(),)
    )["n"]

    # KEV entries linked to this technique
    kev_entries = query("""
        SELECT k.cve_id, k.vendor_project, k.product, k.vulnerability_name,
               k.date_added, k.known_ransomware
        FROM kev_entries k
        JOIN kev_technique_mappings ktm ON k.cve_id = ktm.cve_id
        WHERE ktm.technique_id = ?
        ORDER BY k.date_added DESC
    """, (technique_id.upper(),))

    return {
        **tech,
        "tactics": tactics,
        "sub_techniques": subs,
        "group_count": group_count,
        "software_count": sw_count,
        "kev_entries": kev_entries,
        "kev_count": len(kev_entries),
    }


@app.get("/techniques/{technique_id}/groups", tags=["techniques"])
def get_technique_groups(technique_id: str):
    groups = query("""
        SELECT g.group_id, g.name, g.aliases, gt.use_description
        FROM groups g
        JOIN group_techniques gt ON g.group_id = gt.group_id
        WHERE gt.technique_id = ?
        ORDER BY g.name
    """, (technique_id.upper(),))

    if not groups and not query_one(
        "SELECT technique_id FROM techniques WHERE technique_id = ?",
        (technique_id.upper(),)
    ):
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")

    return {"technique_id": technique_id.upper(), "group_count": len(groups), "groups": groups}


@app.get("/techniques/{technique_id}/software", tags=["techniques"])
def get_technique_software(technique_id: str):
    software = query("""
        SELECT s.software_id, s.name, s.software_type, s.aliases,
               st.use_description
        FROM software s
        JOIN software_techniques st ON s.software_id = st.software_id
        WHERE st.technique_id = ?
        ORDER BY s.name
    """, (technique_id.upper(),))

    return {
        "technique_id": technique_id.upper(),
        "software_count": len(software),
        "software": software
    }


@app.get("/techniques/{technique_id}/compliance", tags=["techniques"])
async def get_technique_compliance(technique_id: str):
    """
    Get compliance controls that mitigate this technique,
    by proxying to the compliance API's ATT&CK endpoint.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                f"{COMPLIANCE_API_URL}/attack/techniques/{technique_id.upper()}"
            )
            if resp.status_code == 404:
                return {
                    "technique_id": technique_id.upper(),
                    "nist_control_count": 0,
                    "nist_controls": [],
                    "transitive_framework_coverage": {},
                    "note": "No compliance mappings available for this technique"
                }
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Compliance API unavailable: {e}"
            )

# =============================================================================
# Groups
# =============================================================================

@app.get("/groups", tags=["groups"])
def list_groups(
    country: Optional[str] = Query(default=None, description="ISO 3166-1 alpha-2 e.g. RU, CN"),
    motivation: Optional[str] = Query(default=None, description="espionage, financial, destruction, hacktivism"),
    sponsor_type: Optional[str] = Query(default=None, description="nation-state, criminal, hacktivist, unknown"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
):
    joins = "LEFT JOIN group_metadata gm ON g.group_id = gm.group_id"
    where = []
    params = []

    if country:
        where.append("gm.country = ?")
        params.append(country.upper())
    if motivation:
        where.append("gm.motivation = ?")
        params.append(motivation.lower())
    if sponsor_type:
        where.append("gm.sponsor_type = ?")
        params.append(sponsor_type.lower())

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = query_one(
        f"SELECT COUNT(*) as n FROM groups g {joins} {where_sql}", tuple(params)
    )["n"]

    offset = (page - 1) * page_size
    results = query(
        f"""SELECT g.group_id, g.name, g.aliases,
                   gm.country, gm.country_name, gm.motivation,
                   gm.sponsor_type, gm.first_seen, gm.target_sectors
            FROM groups g {joins} {where_sql}
            ORDER BY g.name LIMIT ? OFFSET ?""",
        tuple(params) + (page_size, offset)
    )

    for g in results:
        if g.get("target_sectors"):
            try:
                g["target_sectors"] = json.loads(g["target_sectors"])
            except (ValueError, TypeError):
                pass

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "groups": results,
    }


@app.get("/groups/{group_id}", tags=["groups"])
def get_group(group_id: str):
    group = query_one(
        "SELECT * FROM groups WHERE group_id = ?", (group_id.upper(),)
    )
    if not group:
        raise HTTPException(status_code=404, detail=f"Group '{group_id}' not found")

    techniques = query("""
        SELECT t.technique_id, t.name, t.is_subtechnique,
               gt.use_description
        FROM techniques t
        JOIN group_techniques gt ON t.technique_id = gt.technique_id
        WHERE gt.group_id = ? AND t.is_deprecated = 0
        ORDER BY t.technique_id
    """, (group_id.upper(),))

    # Tactics used (derived from techniques)
    tactic_ids = set()
    for tech in techniques:
        rows = query(
            "SELECT tactic_id FROM technique_tactics WHERE technique_id = ?",
            (tech["technique_id"],)
        )
        tactic_ids.update(r["tactic_id"] for r in rows)

    tactics = query(
        f"SELECT tactic_id, name FROM tactics WHERE tactic_id IN "
        f"({','.join('?' * len(tactic_ids))}) ORDER BY tactic_id",
        tuple(tactic_ids)
    ) if tactic_ids else []

    metadata = query_one(
        "SELECT * FROM group_metadata WHERE group_id = ?", (group_id.upper(),)
    )

    if metadata and metadata.get("target_sectors"):
        try:
            metadata["target_sectors"] = json.loads(metadata["target_sectors"])
        except (ValueError, TypeError):
            pass

    return {
        **group,
        "metadata": metadata or {},
        "technique_count": len(techniques),
        "techniques": techniques,
        "tactics_observed": tactics,
    }


@app.get("/groups/{group_id}/techniques", tags=["groups"])
def get_group_techniques(group_id: str):
    group = query_one("SELECT group_id, name FROM groups WHERE group_id = ?",
                      (group_id.upper(),))
    if not group:
        raise HTTPException(status_code=404, detail=f"Group '{group_id}' not found")

    techniques = query("""
        SELECT t.technique_id, t.name, t.is_subtechnique,
               t.platforms, gt.use_description
        FROM techniques t
        JOIN group_techniques gt ON t.technique_id = gt.technique_id
        WHERE gt.group_id = ? AND t.is_deprecated = 0
        ORDER BY t.technique_id
    """, (group_id.upper(),))

    return {**group, "technique_count": len(techniques), "techniques": techniques}


@app.get("/groups/{group_id}/software", tags=["groups"])
def get_group_software(group_id: str):
    group = query_one("SELECT group_id, name FROM groups WHERE group_id = ?",
                      (group_id.upper(),))
    if not group:
        raise HTTPException(status_code=404, detail=f"Group '{group_id}' not found")

    software = query("""
        SELECT s.software_id, s.name, s.software_type, s.aliases, s.platforms
        FROM software s
        JOIN group_software gs ON s.software_id = gs.software_id
        WHERE gs.group_id = ?
        ORDER BY s.name
    """, (group_id.upper(),))

    return {**group, "software_count": len(software), "software": software}

# =============================================================================
# Software
# =============================================================================

@app.get("/software", tags=["software"])
def list_software(
    software_type: Optional[str] = Query(default=None, description="malware or tool"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
):
    where = "WHERE software_type = ?" if software_type else ""
    params = (software_type,) if software_type else ()

    total = query_one(f"SELECT COUNT(*) as n FROM software {where}", params)["n"]
    offset = (page - 1) * page_size
    results = query(
        f"SELECT software_id, name, software_type, aliases, platforms "
        f"FROM software {where} ORDER BY name LIMIT ? OFFSET ?",
        params + (page_size, offset)
    )

    return {
        "total": total, "page": page, "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "software": results,
    }


@app.get("/software/{software_id}", tags=["software"])
def get_software(software_id: str):
    sw = query_one("SELECT * FROM software WHERE software_id = ?", (software_id.upper(),))
    if not sw:
        raise HTTPException(status_code=404, detail=f"Software '{software_id}' not found")

    techniques = query("""
        SELECT t.technique_id, t.name, t.is_subtechnique,
               st.use_description
        FROM techniques t
        JOIN software_techniques st ON t.technique_id = st.technique_id
        WHERE st.software_id = ? AND t.is_deprecated = 0
        ORDER BY t.technique_id
    """, (software_id.upper(),))

    return {**sw, "technique_count": len(techniques), "techniques": techniques}

# =============================================================================
# CISA KEV
# =============================================================================

@app.get("/kev/stats", tags=["kev"])
def kev_stats():
    total = query_one("SELECT COUNT(*) as n FROM kev_entries")["n"]
    ransomware = query_one(
        "SELECT COUNT(*) as n FROM kev_entries WHERE known_ransomware='Known'"
    )["n"]
    recent_30 = query_one(
        "SELECT COUNT(*) as n FROM kev_entries WHERE date_added >= date('now','-30 days')"
    )["n"]
    recent_90 = query_one(
        "SELECT COUNT(*) as n FROM kev_entries WHERE date_added >= date('now','-90 days')"
    )["n"]
    top_vendors = query("""
        SELECT vendor_project, COUNT(*) as count
        FROM kev_entries GROUP BY vendor_project
        ORDER BY count DESC LIMIT 10
    """)
    return {
        "total_entries": total,
        "ransomware_associated": ransomware,
        "added_last_30_days": recent_30,
        "added_last_90_days": recent_90,
        "top_vendors": top_vendors,
    }


@app.get("/kev", tags=["kev"])
def list_kev(
    ransomware_only: bool = Query(default=False),
    vendor: Optional[str] = Query(default=None),
    days: Optional[int] = Query(default=None, description="Added in last N days"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    where = []
    params = []

    if ransomware_only:
        where.append("known_ransomware = 'Known'")
    if vendor:
        where.append("vendor_project LIKE ?")
        params.append(f"%{vendor}%")
    if days:
        where.append("date_added >= date('now', ?)")
        params.append(f"-{days} days")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = query_one(
        f"SELECT COUNT(*) as n FROM kev_entries {where_sql}", tuple(params)
    )["n"]

    offset = (page - 1) * page_size
    results = query(
        f"""SELECT cve_id, vendor_project, product, vulnerability_name,
                   date_added, known_ransomware
            FROM kev_entries {where_sql}
            ORDER BY date_added DESC
            LIMIT ? OFFSET ?""",
        tuple(params) + (page_size, offset)
    )

    return {
        "total": total, "page": page, "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "entries": results,
    }


@app.get("/kev/{cve_id}", tags=["kev"])
def get_kev_entry(cve_id: str):
    entry = query_one(
        "SELECT * FROM kev_entries WHERE cve_id = ?", (cve_id.upper(),)
    )
    if not entry:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not in KEV catalog")

    techniques = query("""
        SELECT t.technique_id, t.name
        FROM techniques t
        JOIN kev_technique_mappings ktm ON t.technique_id = ktm.technique_id
        WHERE ktm.cve_id = ?
    """, (cve_id.upper(),))

    return {**entry, "attack_techniques": techniques}

# =============================================================================
# Search
# =============================================================================

@app.get("/search", tags=["search"])
def search(
    q: str = Query(..., min_length=2),
    types: str = Query(
        default="techniques,groups,software",
        description="Comma-separated: techniques,groups,software,kev"
    ),
    page_size: int = Query(default=20, ge=1, le=100),
):
    """Search across techniques, groups, software, and KEV entries."""
    search_types = [t.strip() for t in types.split(",")]
    term = f"%{q}%"
    results = {}

    if "techniques" in search_types:
        results["techniques"] = query("""
            SELECT technique_id, name, is_subtechnique, platforms
            FROM techniques
            WHERE (technique_id LIKE ? OR name LIKE ? OR description LIKE ?)
              AND is_deprecated = 0 AND is_revoked = 0
            ORDER BY technique_id LIMIT ?
        """, (term, term, term, page_size))

    if "groups" in search_types:
        results["groups"] = query("""
            SELECT group_id, name, aliases
            FROM groups
            WHERE name LIKE ? OR aliases LIKE ? OR description LIKE ?
            ORDER BY name LIMIT ?
        """, (term, term, term, page_size))

    if "software" in search_types:
        results["software"] = query("""
            SELECT software_id, name, software_type, aliases
            FROM software
            WHERE name LIKE ? OR aliases LIKE ? OR description LIKE ?
            ORDER BY name LIMIT ?
        """, (term, term, term, page_size))

    if "kev" in search_types:
        results["kev"] = query("""
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added
            FROM kev_entries
            WHERE cve_id LIKE ? OR product LIKE ? OR vulnerability_name LIKE ?
               OR short_description LIKE ?
            ORDER BY date_added DESC LIMIT ?
        """, (term, term, term, term, page_size))

    total = sum(len(v) for v in results.values())
    return {"query": q, "total_results": total, **results}
