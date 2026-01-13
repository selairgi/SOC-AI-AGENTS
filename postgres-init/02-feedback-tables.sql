-- Operator Feedback Table
-- Stores feedback from SOC operators marking messages as Safe or Threat
-- Survives Docker container deletion (persists in postgres_data volume)

CREATE TABLE IF NOT EXISTS operator_feedback (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(255),

    -- Detection info
    predicted_label VARCHAR(50) NOT NULL,  -- 'safe', 'investigate', 'block'
    actual_label VARCHAR(50) NOT NULL,     -- 'safe' or 'threat'

    -- Scores
    fp_probability FLOAT,
    confidence FLOAT,
    threat_score FLOAT,

    -- Metadata
    detection_method VARCHAR(100),
    reasoning TEXT[],
    suspicious_keywords TEXT[],

    -- Operator info
    operator_id VARCHAR(255),
    operator_notes TEXT,

    -- Timestamps
    message_timestamp TIMESTAMP,
    feedback_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Indexes for fast lookup
    CONSTRAINT unique_alert_feedback UNIQUE (alert_id)
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_feedback_session ON operator_feedback(session_id);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON operator_feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_label ON operator_feedback(actual_label);
CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON operator_feedback(feedback_timestamp DESC);

-- Alert History Table
-- Stores all alerts for feedback reference
CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) NOT NULL UNIQUE,
    message TEXT NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(255),
    src_ip VARCHAR(45),

    -- Alert details
    severity VARCHAR(50),
    threat_type VARCHAR(100),
    detection_method VARCHAR(100),

    -- Scores
    fp_probability FLOAT,
    confidence FLOAT,
    danger_score FLOAT,

    -- Evidence
    reasoning TEXT[],
    suspicious_keywords TEXT[],
    intent_type VARCHAR(100),

    -- Session context
    session_risk_score FLOAT,
    escalation_detected BOOLEAN DEFAULT FALSE,
    slow_injection_detected BOOLEAN DEFAULT FALSE,

    -- Metadata
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Action taken
    recommended_action VARCHAR(50),
    action_taken VARCHAR(50)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_alert_session ON alert_history(session_id);
CREATE INDEX IF NOT EXISTS idx_alert_user ON alert_history(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert_history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alert_history(severity);

COMMENT ON TABLE operator_feedback IS 'Operator feedback for adaptive learning - persists across container restarts';
COMMENT ON TABLE alert_history IS 'Complete alert history for feedback and analysis';
