-- ============================================================================
-- SECFORIT Day0 Vulnerability Tracker - Initial Schema
-- Database: Supabase PostgreSQL
-- Version: 1.0
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";    -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- Trigram similarity search

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

CREATE TYPE cvss_version AS ENUM ('v2.0', 'v3.0', 'v3.1', 'v4.0');
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN');

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- CVEs table - primary store for all CVE data
CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY,                    -- e.g. CVE-2024-1234
  description_en TEXT,
  cvss_best_score NUMERIC(3,1),               -- precomputed best CVSS score
  cvss_best_severity severity_level DEFAULT 'UNKNOWN',
  published TIMESTAMPTZ,
  last_modified TIMESTAMPTZ,
  source_identifier TEXT,                     -- NVD source identifier
  vuln_status TEXT,                           -- e.g. Analyzed, Modified, Rejected

  -- CISA KEV fields
  is_kev BOOLEAN DEFAULT FALSE,
  cisa_date_added DATE,
  cisa_due_date DATE,
  cisa_required_action TEXT,
  cisa_known_ransomware_use TEXT,
  cisa_vulnerability_name TEXT,

  -- Product info (denormalized for quick display)
  primary_vendor TEXT,
  primary_product TEXT,

  -- JSONB for full NVD response and complex nested data
  raw_data JSONB,                             -- full NVD API response
  configurations JSONB,                       -- CPE configurations tree
  metrics JSONB,                              -- all CVSS metric objects

  -- Full-text search
  search_vector TSVECTOR,

  -- Timestamps
  ingested_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- CVE References
CREATE TABLE cve_references (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  source TEXT,
  tags TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CVE Weaknesses (CWE mappings)
CREATE TABLE cve_weaknesses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  cwe_id TEXT NOT NULL,                       -- e.g. CWE-79
  source TEXT,                                -- e.g. nvd@nist.gov
  source_type TEXT,                           -- Primary or Secondary
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CVSS Metrics (all versions per CVE)
CREATE TABLE cvss_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  version cvss_version NOT NULL,
  source TEXT,
  source_type TEXT,                           -- Primary or Secondary
  base_score NUMERIC(3,1),
  base_severity TEXT,
  vector_string TEXT,
  exploitability_score NUMERIC(3,1),
  impact_score NUMERIC(3,1),
  metric_data JSONB,                          -- full CVSS metric object
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CPE Matches (flattened for vendor/product search)
CREATE TABLE cve_cpe_matches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  vendor TEXT,
  product TEXT,
  criteria TEXT,                              -- full CPE 2.3 string
  vulnerable BOOLEAN DEFAULT TRUE,
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including TEXT,
  version_end_excluding TEXT,
  match_criteria_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- AI Summaries (versioned)
CREATE TABLE ai_summaries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  summary_text TEXT NOT NULL,
  model TEXT NOT NULL,                        -- e.g. llama-3.3-70b-versatile
  tokens_used INTEGER,
  processing_time_ms INTEGER,
  is_latest BOOLEAN DEFAULT TRUE,
  trusted_references JSONB DEFAULT '[]',      -- array of {url, source, tags[]}
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security Bulletins
CREATE TABLE security_bulletins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  bulletin_markdown TEXT NOT NULL,
  bulletin_date DATE NOT NULL DEFAULT CURRENT_DATE,
  cve_ids TEXT[] DEFAULT '{}',
  severity_summary JSONB,                     -- {critical: N, high: N, ...}
  model TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- FUTURE TABLES (created now, unused initially)
-- ============================================================================

-- User profiles (extends Supabase auth.users)
CREATE TABLE user_profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT,
  organization TEXT,
  role TEXT DEFAULT 'viewer',
  preferences JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Watchlists
CREATE TABLE watchlists (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  filters JSONB DEFAULT '{}',                 -- saved filter criteria
  cve_ids TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert rules
CREATE TABLE alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  conditions JSONB NOT NULL,                  -- {min_cvss, severities, vendors, keywords}
  notification_channels JSONB DEFAULT '[]',   -- [{type: email/webhook, target: ...}]
  last_triggered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Saved queries
CREATE TABLE saved_queries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  query_params JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CVE Comments
CREATE TABLE cve_comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  comment_text TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Bulletin-CVE junction
CREATE TABLE bulletin_cves (
  bulletin_id UUID NOT NULL REFERENCES security_bulletins(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  PRIMARY KEY (bulletin_id, cve_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- CVEs indexes
CREATE INDEX idx_cves_published ON cves(published DESC);
CREATE INDEX idx_cves_last_modified ON cves(last_modified DESC);
CREATE INDEX idx_cves_cvss_score ON cves(cvss_best_score DESC NULLS LAST);
CREATE INDEX idx_cves_severity ON cves(cvss_best_severity);
CREATE INDEX idx_cves_vendor ON cves(primary_vendor);
CREATE INDEX idx_cves_product ON cves(primary_product);
CREATE INDEX idx_cves_vendor_product ON cves(primary_vendor, primary_product);
CREATE INDEX idx_cves_search_vector ON cves USING GIN(search_vector);
CREATE INDEX idx_cves_raw_data ON cves USING GIN(raw_data);
CREATE INDEX idx_cves_description_trgm ON cves USING GIN(description_en gin_trgm_ops);

-- Partial indexes
CREATE INDEX idx_cves_kev ON cves(cisa_date_added DESC) WHERE is_kev = TRUE;
CREATE INDEX idx_cves_critical ON cves(published DESC) WHERE cvss_best_severity = 'CRITICAL';

-- References indexes
CREATE INDEX idx_cve_references_cve_id ON cve_references(cve_id);
CREATE INDEX idx_cve_references_tags ON cve_references USING GIN(tags);

-- Weaknesses indexes
CREATE INDEX idx_cve_weaknesses_cve_id ON cve_weaknesses(cve_id);
CREATE INDEX idx_cve_weaknesses_cwe_id ON cve_weaknesses(cwe_id);

-- CVSS metrics indexes
CREATE INDEX idx_cvss_metrics_cve_id ON cvss_metrics(cve_id);
CREATE INDEX idx_cvss_metrics_score ON cvss_metrics(base_score DESC);

-- CPE matches indexes
CREATE INDEX idx_cpe_matches_cve_id ON cve_cpe_matches(cve_id);
CREATE INDEX idx_cpe_matches_vendor ON cve_cpe_matches(vendor);
CREATE INDEX idx_cpe_matches_product ON cve_cpe_matches(product);
CREATE INDEX idx_cpe_matches_vendor_product ON cve_cpe_matches(vendor, product);

-- AI summaries indexes
CREATE INDEX idx_ai_summaries_cve_id ON ai_summaries(cve_id);
CREATE INDEX idx_ai_summaries_latest ON ai_summaries(cve_id) WHERE is_latest = TRUE;

-- Security bulletins indexes
CREATE INDEX idx_bulletins_date ON security_bulletins(bulletin_date DESC);
CREATE INDEX idx_bulletins_cve_ids ON security_bulletins USING GIN(cve_ids);

-- Future tables indexes
CREATE INDEX idx_watchlists_user ON watchlists(user_id);
CREATE INDEX idx_alert_rules_user ON alert_rules(user_id);
CREATE INDEX idx_saved_queries_user ON saved_queries(user_id);
CREATE INDEX idx_cve_comments_cve ON cve_comments(cve_id);
CREATE INDEX idx_cve_comments_user ON cve_comments(user_id);

-- ============================================================================
-- TRIGGERS & FUNCTIONS
-- ============================================================================

-- Auto-update search_vector on CVE insert/update
CREATE OR REPLACE FUNCTION update_cve_search_vector()
RETURNS TRIGGER AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', COALESCE(NEW.cve_id, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(NEW.description_en, '')), 'B') ||
    setweight(to_tsvector('english', COALESCE(NEW.primary_vendor, '')), 'C') ||
    setweight(to_tsvector('english', COALESCE(NEW.primary_product, '')), 'C') ||
    setweight(to_tsvector('english', COALESCE(NEW.cisa_vulnerability_name, '')), 'B');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cves_search_vector
  BEFORE INSERT OR UPDATE ON cves
  FOR EACH ROW
  EXECUTE FUNCTION update_cve_search_vector();

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cves_updated_at
  BEFORE UPDATE ON cves
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_bulletins_updated_at
  BEFORE UPDATE ON security_bulletins
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_user_profiles_updated_at
  BEFORE UPDATE ON user_profiles
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- Mark previous AI summaries as not latest when new one is inserted
CREATE OR REPLACE FUNCTION mark_previous_summaries()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_latest = TRUE THEN
    UPDATE ai_summaries
    SET is_latest = FALSE
    WHERE cve_id = NEW.cve_id AND id != NEW.id AND is_latest = TRUE;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ai_summaries_latest
  AFTER INSERT ON ai_summaries
  FOR EACH ROW
  EXECUTE FUNCTION mark_previous_summaries();

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Dashboard view: CVEs with latest AI summary
CREATE OR REPLACE VIEW v_cves_with_summary AS
SELECT
  c.*,
  s.summary_text AS ai_summary,
  s.model AS ai_model,
  s.created_at AS summary_generated_at,
  s.trusted_references
FROM cves c
LEFT JOIN ai_summaries s ON c.cve_id = s.cve_id AND s.is_latest = TRUE;

-- KEV overview
CREATE OR REPLACE VIEW v_kev_vulnerabilities AS
SELECT
  cve_id,
  description_en,
  cvss_best_score,
  cvss_best_severity,
  published,
  cisa_date_added,
  cisa_due_date,
  cisa_required_action,
  cisa_known_ransomware_use,
  cisa_vulnerability_name,
  primary_vendor,
  primary_product
FROM cves
WHERE is_kev = TRUE
ORDER BY cisa_date_added DESC;

-- Severity distribution stats
CREATE OR REPLACE VIEW v_severity_stats AS
SELECT
  cvss_best_severity AS severity,
  COUNT(*) AS count,
  ROUND(AVG(cvss_best_score), 1) AS avg_score,
  MAX(cvss_best_score) AS max_score,
  COUNT(*) FILTER (WHERE is_kev) AS kev_count
FROM cves
WHERE cvss_best_severity IS NOT NULL
GROUP BY cvss_best_severity
ORDER BY
  CASE cvss_best_severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
    WHEN 'NONE' THEN 5
    ELSE 6
  END;

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_weaknesses ENABLE ROW LEVEL SECURITY;
ALTER TABLE cvss_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_cpe_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_bulletins ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulletin_cves ENABLE ROW LEVEL SECURITY;

-- Public read access for CVE data (anon + authenticated)
CREATE POLICY "Public read CVEs" ON cves FOR SELECT USING (true);
CREATE POLICY "Public read references" ON cve_references FOR SELECT USING (true);
CREATE POLICY "Public read weaknesses" ON cve_weaknesses FOR SELECT USING (true);
CREATE POLICY "Public read cvss" ON cvss_metrics FOR SELECT USING (true);
CREATE POLICY "Public read cpe" ON cve_cpe_matches FOR SELECT USING (true);
CREATE POLICY "Public read summaries" ON ai_summaries FOR SELECT USING (true);
CREATE POLICY "Public read bulletins" ON security_bulletins FOR SELECT USING (true);
CREATE POLICY "Public read bulletin_cves" ON bulletin_cves FOR SELECT USING (true);

-- Service role write access for CVE data (server-side only)
CREATE POLICY "Service write CVEs" ON cves FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write references" ON cve_references FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write weaknesses" ON cve_weaknesses FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write cvss" ON cvss_metrics FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write cpe" ON cve_cpe_matches FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write summaries" ON ai_summaries FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write bulletins" ON security_bulletins FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service write bulletin_cves" ON bulletin_cves FOR ALL USING (auth.role() = 'service_role');

-- User data: scoped to auth.uid()
CREATE POLICY "Users own profile" ON user_profiles FOR ALL USING (id = auth.uid());
CREATE POLICY "Users own watchlists" ON watchlists FOR ALL USING (user_id = auth.uid());
CREATE POLICY "Users own alerts" ON alert_rules FOR ALL USING (user_id = auth.uid());
CREATE POLICY "Users own queries" ON saved_queries FOR ALL USING (user_id = auth.uid());
CREATE POLICY "Users own comments" ON cve_comments FOR ALL USING (user_id = auth.uid());
-- Allow reading other users' comments on CVEs
CREATE POLICY "Public read comments" ON cve_comments FOR SELECT USING (true);
