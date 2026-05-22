-- migrate_001_group_enrichment.sql
-- Additive schema migration — safe to run against live threat.db
-- Adds group_metadata, campaigns, campaign_groups, campaign_techniques,
-- and group_software tables.

-- =============================================================================
-- group_metadata
-- =============================================================================
CREATE TABLE IF NOT EXISTS group_metadata (
    group_id        TEXT NOT NULL UNIQUE,
    country         TEXT,           -- ISO 3166-1 alpha-2 e.g. "RU", "CN", "KP", "IR"
    country_name    TEXT,           -- "Russia", "China", "North Korea", "Iran"
    motivation      TEXT,           -- "espionage", "financial", "destruction", "hacktivism"
    first_seen      TEXT,           -- year e.g. "2008"
    target_sectors  TEXT,           -- JSON array e.g. ["Government","Defense","Energy"]
    sponsor_type    TEXT,           -- "nation-state", "criminal", "hacktivist", "unknown"
    notes           TEXT,           -- free-form attribution notes
    FOREIGN KEY (group_id) REFERENCES groups(group_id)
);

CREATE INDEX IF NOT EXISTS idx_group_metadata_country    ON group_metadata(country);
CREATE INDEX IF NOT EXISTS idx_group_metadata_motivation ON group_metadata(motivation);
CREATE INDEX IF NOT EXISTS idx_group_metadata_sponsor    ON group_metadata(sponsor_type);

-- =============================================================================
-- campaigns
-- =============================================================================
CREATE TABLE IF NOT EXISTS campaigns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL UNIQUE,   -- e.g. C0024
    name        TEXT NOT NULL,
    description TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    url         TEXT,
    stix_id     TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_campaigns_id ON campaigns(campaign_id);

CREATE TABLE IF NOT EXISTS campaign_groups (
    campaign_id TEXT NOT NULL,
    group_id    TEXT NOT NULL,
    PRIMARY KEY (campaign_id, group_id)
);

CREATE TABLE IF NOT EXISTS campaign_techniques (
    campaign_id     TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    use_description TEXT,
    PRIMARY KEY (campaign_id, technique_id)
);

-- =============================================================================
-- group_software
-- =============================================================================
CREATE TABLE IF NOT EXISTS group_software (
    group_id    TEXT NOT NULL,
    software_id TEXT NOT NULL,
    PRIMARY KEY (group_id, software_id)
);

CREATE INDEX IF NOT EXISTS idx_group_software_group    ON group_software(group_id);
CREATE INDEX IF NOT EXISTS idx_group_software_software ON group_software(software_id);
