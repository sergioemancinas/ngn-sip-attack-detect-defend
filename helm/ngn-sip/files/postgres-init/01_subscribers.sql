CREATE TABLE IF NOT EXISTS sip_subscribers (
    extension TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO sip_subscribers (extension, display_name)
VALUES
    ('1000', 'SIPp caller'),
    ('1001', 'SIPp callee')
ON CONFLICT (extension) DO NOTHING;
