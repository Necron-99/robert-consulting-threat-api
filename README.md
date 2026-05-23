# robert-consulting-threat-api

A production threat intelligence API serving MITRE ATT&CK Enterprise data, CISA Known Exploited Vulnerabilities, and cross-framework compliance mappings — built to support threat-informed defense at the control level.

Live at **[threat.robertconsulting.net](https://threat.robertconsulting.net)**

---

## What it does

Most security tooling treats threat intelligence and compliance as separate workstreams. This API bridges them — every ATT&CK technique carries its KEV exposure, group usage context, and the compliance controls that mitigate it, all queryable in a single request.

**Data coverage:**
- 656 ATT&CK Enterprise techniques (MITRE v16.1)
- 175 threat actor groups with country attribution, motivation, sponsor type, and target sectors
- 714 software entries (malware and tools)
- 1,599 CISA KEV entries with 1,177 CVE-to-technique mappings (CTID Mappings Explorer)
- Cross-framework compliance coverage via the [Compliance Mapper](https://compliance.robertconsulting.net)

---

## API

Built with **FastAPI** on **Python 3.12**. Read-only SQLite backend fetched from S3 on pod start. Full OpenAPI docs at [api.threat.robertconsulting.net/docs](https://api.threat.robertconsulting.net/docs).

### Key endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /stats` | Platform summary counts |
| `GET /tactics` | All 14 ATT&CK tactics with technique counts |
| `GET /techniques/{id}` | Full technique detail — platforms, detection, KEV entries, compliance controls |
| `GET /techniques/{id}/groups` | Threat actor groups observed using this technique |
| `GET /groups` | All groups — filterable by `country`, `motivation`, `sponsor_type` |
| `GET /groups/{id}` | Group profile with full TTP list, attribution metadata, and target sectors |
| `GET /kev` | CISA KEV catalog — filterable by vendor, ransomware association, recency |
| `GET /kev/{cve_id}` | Single KEV entry with mapped ATT&CK techniques |
| `GET /heatmap/data` | Pre-aggregated tactic/technique data for Navigator-style visualization |
| `GET /stats/by-country` | Group and technique counts by attributed nation-state |
| `GET /search` | Full-text search across techniques, groups, software, and KEV entries |

### Example

```bash
# What techniques is APT29 known to use, and which compliance controls address them?
curl https://api.threat.robertconsulting.net/groups/G0016 | jq '.technique_count'
# 121

curl https://api.threat.robertconsulting.net/techniques/T1078/compliance | jq '.nist_control_count'
# 29
```

---

## Architecture

```
CloudFront / Route 53
       │
   ingress-nginx (k3s, Hetzner)
       │
   threat-api pod
   ├── init container: fetch threat.db from S3
   └── FastAPI (uvicorn, single worker)
           │
       SQLite (read-only, immutable mount)
           │
       Compliance API proxy (cross-framework mappings)
```

- **Kubernetes** — k3s on Hetzner CX33
- **Container** — multi-stage Python 3.12 slim, non-root user
- **Database** — SQLite, S3-backed, fetched by init container on pod start
- **Observability** — Prometheus metrics via `prometheus-fastapi-instrumentator`, Grafana dashboards
- **CI/CD** — GitHub Actions → GHCR image push → `kubectl rollout restart`

---

## Data Sources

| Source | License | Coverage |
|--------|---------|----------|
| [MITRE ATT&CK Enterprise](https://attack.mitre.org) | Apache 2.0 | Techniques, tactics, groups, software |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Public Domain | 1,599 actively exploited CVEs |
| [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) | Apache 2.0 | CVE-to-ATT&CK technique mappings |

Group attribution data (country, motivation, sponsor type, target sectors) is curated from public sources including MITRE, Mandiant APT profiles, CrowdStrike adversary naming, and US government advisories.

---

## Related

- **[robert-consulting-compliance-api](https://github.com/Necron-99/robert-consulting-compliance-api)** — Cross-framework compliance mapping API (NIST 800-53, FedRAMP, ISO 27001, SOC 2, HIPAA, CMMC, GDPR)
- **[robert-consulting-platform-ops](https://github.com/Necron-99/robert-consulting-platform-ops)** — Kubernetes platform operations and monitoring stack
- **[robert-consulting-content](https://github.com/Necron-99/robert-consulting-content)** — Frontend UIs for both tools

---

## Disclaimer

ATT&CK data: MITRE ATT&CK Enterprise v16.1 — Apache 2.0
KEV data: CISA Known Exploited Vulnerabilities — Public Domain
Compliance mappings: CTID Mappings Explorer — Apache 2.0

Reference only — not legal or operational advice.

© 2026 Robert Consulting LLC. All rights reserved.
