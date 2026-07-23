-- Minimal Homer 7 SIPCAPTURE schema for the local NGN SIP lab.
-- Source references:
-- - https://github.com/sipcapture/homer/wiki/Quick-Install
-- - https://github-wiki-see.page/m/sipcapture/homer-app/wiki/Examples%3A-Correlation-MAPPING
-- - https://pkg.go.dev/github.com/sipcapture/heplify-server/config
--
-- HEPlify-server can create and rotate Homer 7 tables at runtime. This file
-- seeds the stable base tables used by homer-app mapping queries so the local
-- stack starts with explicit, reviewable table names.

SELECT 'CREATE DATABASE homer_config OWNER homer_user'
WHERE NOT EXISTS (
  SELECT FROM pg_database WHERE datname = 'homer_config'
)
\gexec

CREATE TABLE IF NOT EXISTS hep_proto_1_default (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw TEXT NOT NULL DEFAULT '',
  raw_header TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hep_proto_1_call (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw TEXT NOT NULL DEFAULT '',
  raw_header TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hep_proto_35_default (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw TEXT NOT NULL DEFAULT '',
  raw_header TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hep_proto_100_default (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw TEXT NOT NULL DEFAULT '',
  raw_header TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS isup_capture_all (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw TEXT NOT NULL DEFAULT '',
  raw_header TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS location (
  id BIGSERIAL PRIMARY KEY,
  node TEXT NOT NULL DEFAULT 'localnode',
  host TEXT NOT NULL DEFAULT '',
  ip INET,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stats_data (
  id BIGSERIAL PRIMARY KEY,
  sid TEXT NOT NULL DEFAULT '',
  create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  target_name TEXT NOT NULL DEFAULT '',
  target_ip TEXT NOT NULL DEFAULT '',
  protocol_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_header JSONB NOT NULL DEFAULT '{}'::jsonb,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS hep_proto_1_default_create_date_idx ON hep_proto_1_default (create_date);
CREATE INDEX IF NOT EXISTS hep_proto_1_default_sid_idx ON hep_proto_1_default (sid);
CREATE INDEX IF NOT EXISTS hep_proto_1_default_data_header_gin_idx ON hep_proto_1_default USING GIN (data_header);
CREATE INDEX IF NOT EXISTS hep_proto_1_default_callid_idx ON hep_proto_1_default ((data_header->>'callid'));

CREATE INDEX IF NOT EXISTS hep_proto_1_call_create_date_idx ON hep_proto_1_call (create_date);
CREATE INDEX IF NOT EXISTS hep_proto_1_call_sid_idx ON hep_proto_1_call (sid);
CREATE INDEX IF NOT EXISTS hep_proto_1_call_data_header_gin_idx ON hep_proto_1_call USING GIN (data_header);
CREATE INDEX IF NOT EXISTS hep_proto_1_call_callid_idx ON hep_proto_1_call ((data_header->>'callid'));

CREATE INDEX IF NOT EXISTS hep_proto_35_default_create_date_idx ON hep_proto_35_default (create_date);
CREATE INDEX IF NOT EXISTS hep_proto_35_default_sid_idx ON hep_proto_35_default (sid);
CREATE INDEX IF NOT EXISTS hep_proto_35_default_data_header_gin_idx ON hep_proto_35_default USING GIN (data_header);

CREATE INDEX IF NOT EXISTS hep_proto_100_default_create_date_idx ON hep_proto_100_default (create_date);
CREATE INDEX IF NOT EXISTS hep_proto_100_default_sid_idx ON hep_proto_100_default (sid);
CREATE INDEX IF NOT EXISTS hep_proto_100_default_data_header_gin_idx ON hep_proto_100_default USING GIN (data_header);

CREATE INDEX IF NOT EXISTS isup_capture_all_create_date_idx ON isup_capture_all (create_date);
CREATE INDEX IF NOT EXISTS isup_capture_all_sid_idx ON isup_capture_all (sid);
CREATE INDEX IF NOT EXISTS isup_capture_all_data_header_gin_idx ON isup_capture_all USING GIN (data_header);

CREATE INDEX IF NOT EXISTS location_node_idx ON location (node);
CREATE INDEX IF NOT EXISTS location_ip_idx ON location (ip);
CREATE INDEX IF NOT EXISTS stats_data_create_date_idx ON stats_data (create_date);
CREATE INDEX IF NOT EXISTS stats_data_target_name_idx ON stats_data (target_name);
