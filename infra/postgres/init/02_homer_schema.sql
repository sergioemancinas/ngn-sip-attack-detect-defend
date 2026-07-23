CREATE SCHEMA IF NOT EXISTS homer;

CREATE TABLE IF NOT EXISTS homer.capture_placeholder (
    id BIGSERIAL PRIMARY KEY,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO homer.capture_placeholder (note)
VALUES ('Placeholder schema; the live Homer 7 capture schema is seeded by the homer stack in infra/homer/postgres-init.')
ON CONFLICT DO NOTHING;
