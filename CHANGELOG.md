# Changelog

All notable changes to the Threat Intelligence API are documented here.

---

## [Unreleased]

---

## [1.2.0] — 2026-05-23

### Added
- `GET /heatmap/data` — single-request endpoint returning all tactics, techniques,
  group usage counts, and KEV counts for Navigator-style heatmap rendering
- `GET /groups/{id}/software` — software used by a threat actor group
- `GET /stats/by-country` — group and technique counts aggregated by attributed country
- Group enrichment: `group_metadata` table with country attribution, motivation,
  sponsor type, first seen year, target sectors, and attribution notes
  (175 groups, 100% coverage; 11 genuinely unattributed)
- Group list filtering by `country`, `motivation`, and `sponsor_type` query params
- KEV-to-ATT&CK technique mappings: 1,177 mappings across 419 KEV entries
  sourced from CTID Mappings Explorer (ATT&CK v16.1)
- Prometheus metrics via `prometheus-fastapi-instrumentator`
- Share/permalink buttons on all four detail page types (frontend)
- ATT&CK Navigator-style heatmap with group usage and KEV presence modes (frontend)

### Changed
- `GET /tactics` now returns correct `technique_count` per tactic
- `GET /groups` list response now includes enrichment fields from `group_metadata`
- `GET /groups/{id}` detail response now includes `metadata` block with parsed
  `target_sectors` JSON array

### Fixed
- `kev_technique_mappings` table was empty after initial import — seeded with
  CTID data via `import_kev_mappings.py`

---

## [1.1.0] — 2026-05-22

### Added
- `GET /groups/{id}/software` endpoint
- `GET /stats/by-country` endpoint
- Schema migration: `group_metadata`, `campaigns`, `campaign_groups`,
  `campaign_techniques`, `group_software` tables
- `seed_group_metadata.py` — group attribution seed script with `--dry-run` support
- `migrate_001_group_enrichment.sql` — additive schema migration

### Infrastructure
- `platform-ops` submodule added
- `.gitignore` added (Python, secrets, DB files, OS/editor artifacts)
- GitHub Actions updated to Node.js 24 compatible action versions

---

## [1.0.0] — 2026-05-21

### Added
- Initial release
- `GET /health` — liveness probe
- `GET /stats` — summary counts
- `GET /tactics` / `GET /tactics/{tactic_id}` — tactic list and detail
- `GET /techniques` — paginated, filterable technique list
- `GET /techniques/{id}` — full technique detail with KEV entries
- `GET /techniques/{id}/groups` — groups using a technique
- `GET /techniques/{id}/software` — software implementing a technique
- `GET /techniques/{id}/compliance` — compliance controls via compliance API proxy
- `GET /groups` — threat actor group list
- `GET /groups/{id}` — group detail with full TTP list
- `GET /groups/{id}/techniques` — techniques used by a group
- `GET /software` / `GET /software/{id}` — software list and detail
- `GET /kev` — CISA KEV catalog (paginated, filterable)
- `GET /kev/{cve_id}` — single KEV entry with technique mappings
- `GET /kev/stats` — KEV summary statistics
- `GET /search` — full-text search across techniques, groups, software, KEV
- Multi-stage Docker build (Python 3.12 slim, non-root user)
- Kubernetes manifests: namespace, cluster-issuer, deployment, service, ingress
- GitHub Actions CI/CD → GHCR image push

### Data
- MITRE ATT&CK Enterprise v16.1 (656 techniques, 14 tactics, 175 groups, 714 software)
- CISA KEV catalog (1,599 entries as of 2026-05-20)
