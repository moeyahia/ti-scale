import type { Migration } from "../types";

export const searchMigration: Migration = {
  version: 3,
  name: "local_full_text_search",
  sql: String.raw`
CREATE VIRTUAL TABLE messages_fts USING fts5(
  body,
  content = 'messages',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, body) VALUES (NEW.rowid, NEW.body);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, body) VALUES ('delete', OLD.rowid, OLD.body);
END;
CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, body) VALUES ('delete', OLD.rowid, OLD.body);
  INSERT INTO messages_fts(rowid, body) VALUES (NEW.rowid, NEW.body);
END;
INSERT INTO messages_fts(messages_fts) VALUES ('rebuild');

CREATE VIRTUAL TABLE evidence_fts USING fts5(
  summary,
  extracted_text,
  content = 'evidence',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER evidence_fts_insert AFTER INSERT ON evidence BEGIN
  INSERT INTO evidence_fts(rowid, summary, extracted_text)
  VALUES (NEW.rowid, NEW.summary, NEW.extracted_text);
END;
CREATE TRIGGER evidence_fts_delete AFTER DELETE ON evidence BEGIN
  INSERT INTO evidence_fts(evidence_fts, rowid, summary, extracted_text)
  VALUES ('delete', OLD.rowid, OLD.summary, OLD.extracted_text);
END;
CREATE TRIGGER evidence_fts_update AFTER UPDATE ON evidence BEGIN
  INSERT INTO evidence_fts(evidence_fts, rowid, summary, extracted_text)
  VALUES ('delete', OLD.rowid, OLD.summary, OLD.extracted_text);
  INSERT INTO evidence_fts(rowid, summary, extracted_text)
  VALUES (NEW.rowid, NEW.summary, NEW.extracted_text);
END;
INSERT INTO evidence_fts(evidence_fts) VALUES ('rebuild');

CREATE VIRTUAL TABLE findings_fts USING fts5(
  title,
  description,
  impact,
  remediation,
  content = 'findings',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER findings_fts_insert AFTER INSERT ON findings BEGIN
  INSERT INTO findings_fts(rowid, title, description, impact, remediation)
  VALUES (NEW.rowid, NEW.title, NEW.description, NEW.impact, NEW.remediation);
END;
CREATE TRIGGER findings_fts_delete AFTER DELETE ON findings BEGIN
  INSERT INTO findings_fts(findings_fts, rowid, title, description, impact, remediation)
  VALUES ('delete', OLD.rowid, OLD.title, OLD.description, OLD.impact, OLD.remediation);
END;
CREATE TRIGGER findings_fts_update AFTER UPDATE ON findings BEGIN
  INSERT INTO findings_fts(findings_fts, rowid, title, description, impact, remediation)
  VALUES ('delete', OLD.rowid, OLD.title, OLD.description, OLD.impact, OLD.remediation);
  INSERT INTO findings_fts(rowid, title, description, impact, remediation)
  VALUES (NEW.rowid, NEW.title, NEW.description, NEW.impact, NEW.remediation);
END;
INSERT INTO findings_fts(findings_fts) VALUES ('rebuild');

CREATE VIRTUAL TABLE lessons_fts USING fts5(
  statement,
  expected_benefit,
  risk,
  content = 'lessons',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER lessons_fts_insert AFTER INSERT ON lessons BEGIN
  INSERT INTO lessons_fts(rowid, statement, expected_benefit, risk)
  VALUES (NEW.rowid, NEW.statement, NEW.expected_benefit, NEW.risk);
END;
CREATE TRIGGER lessons_fts_delete AFTER DELETE ON lessons BEGIN
  INSERT INTO lessons_fts(lessons_fts, rowid, statement, expected_benefit, risk)
  VALUES ('delete', OLD.rowid, OLD.statement, OLD.expected_benefit, OLD.risk);
END;
CREATE TRIGGER lessons_fts_update AFTER UPDATE ON lessons BEGIN
  INSERT INTO lessons_fts(lessons_fts, rowid, statement, expected_benefit, risk)
  VALUES ('delete', OLD.rowid, OLD.statement, OLD.expected_benefit, OLD.risk);
  INSERT INTO lessons_fts(rowid, statement, expected_benefit, risk)
  VALUES (NEW.rowid, NEW.statement, NEW.expected_benefit, NEW.risk);
END;
INSERT INTO lessons_fts(lessons_fts) VALUES ('rebuild');

CREATE VIRTUAL TABLE memory_nodes_fts USING fts5(
  title,
  summary,
  body,
  content = 'memory_nodes',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER memory_nodes_fts_insert AFTER INSERT ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(rowid, title, summary, body)
  VALUES (NEW.rowid, NEW.title, NEW.summary, NEW.body);
END;
CREATE TRIGGER memory_nodes_fts_delete AFTER DELETE ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(memory_nodes_fts, rowid, title, summary, body)
  VALUES ('delete', OLD.rowid, OLD.title, OLD.summary, OLD.body);
END;
CREATE TRIGGER memory_nodes_fts_update AFTER UPDATE ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(memory_nodes_fts, rowid, title, summary, body)
  VALUES ('delete', OLD.rowid, OLD.title, OLD.summary, OLD.body);
  INSERT INTO memory_nodes_fts(rowid, title, summary, body)
  VALUES (NEW.rowid, NEW.title, NEW.summary, NEW.body);
END;
INSERT INTO memory_nodes_fts(memory_nodes_fts) VALUES ('rebuild');

CREATE VIRTUAL TABLE structured_logs_fts USING fts5(
  message,
  content = 'structured_logs',
  content_rowid = 'rowid',
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER structured_logs_fts_insert AFTER INSERT ON structured_logs BEGIN
  INSERT INTO structured_logs_fts(rowid, message) VALUES (NEW.rowid, NEW.message);
END;
CREATE TRIGGER structured_logs_fts_delete AFTER DELETE ON structured_logs BEGIN
  INSERT INTO structured_logs_fts(structured_logs_fts, rowid, message)
  VALUES ('delete', OLD.rowid, OLD.message);
END;
CREATE TRIGGER structured_logs_fts_update AFTER UPDATE ON structured_logs BEGIN
  INSERT INTO structured_logs_fts(structured_logs_fts, rowid, message)
  VALUES ('delete', OLD.rowid, OLD.message);
  INSERT INTO structured_logs_fts(rowid, message) VALUES (NEW.rowid, NEW.message);
END;
INSERT INTO structured_logs_fts(structured_logs_fts) VALUES ('rebuild');
`,
};
