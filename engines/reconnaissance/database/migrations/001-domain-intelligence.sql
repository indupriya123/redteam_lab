CREATE TABLE IF NOT EXISTS intelligence_records (
    assessment TEXT NOT NULL,
    category TEXT NOT NULL,
    id TEXT NOT NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    document TEXT NOT NULL,
    PRIMARY KEY (assessment, category, id)
);
CREATE INDEX IF NOT EXISTS intelligence_category
    ON intelligence_records(assessment, category, status);
CREATE TABLE IF NOT EXISTS executions (
    id TEXT PRIMARY KEY,
    assessment TEXT NOT NULL,
    agent TEXT NOT NULL,
    skill TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS execution_assessment ON executions(assessment, status);
