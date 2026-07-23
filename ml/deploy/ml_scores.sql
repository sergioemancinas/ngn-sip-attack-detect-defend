CREATE TABLE IF NOT EXISTS ngn_sip.ml_scores
( scored_at DateTime64(3) DEFAULT now64(3), bucket DateTime, src_ip String,
  predicted_class LowCardinality(String), proba Float32, anomaly_score Float32, model_version String )
ENGINE = MergeTree PARTITION BY toYYYYMMDD(bucket) ORDER BY (bucket, src_ip)
TTL toDateTime(bucket) + INTERVAL 30 DAY;
