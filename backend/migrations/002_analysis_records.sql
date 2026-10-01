CREATE TABLE IF NOT EXISTS correlations(
  correlation_id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id),
  analysis_run_id TEXT NOT NULL REFERENCES jobs(id),
  endpoint_id TEXT NOT NULL,
  source_evidence_ids TEXT NOT NULL,
  target_evidence_ids TEXT NOT NULL,
  source_entity TEXT NOT NULL,
  target_entity TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  reason TEXT NOT NULL,
  confidence TEXT NOT NULL,
  profile_version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  provenance TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS correlations_run ON correlations(analysis_run_id,created_at);
CREATE TABLE IF NOT EXISTS timeline_events(
  timeline_event_id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id),
  analysis_run_id TEXT NOT NULL REFERENCES jobs(id),
  endpoint_id TEXT NOT NULL,
  event_time TEXT,
  observed_at TEXT NOT NULL,
  collected_at TEXT,
  timestamp_meaning TEXT NOT NULL,
  uncertainty TEXT NOT NULL,
  event_type TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,
  detection_ids TEXT NOT NULL,
  provenance TEXT NOT NULL,
  summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS timeline_run ON timeline_events(analysis_run_id,event_time,timeline_event_id);
