CREATE TABLE gateway_identity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    role text NOT NULL CHECK(role IN ('trade','verification')),
    fingerprint_key bytea NOT NULL
);
CREATE TABLE executors (
    id text PRIMARY KEY,
    heartbeat timestamptz NOT NULL DEFAULT clock_timestamp(),
    fenced boolean NOT NULL DEFAULT false
);
CREATE TABLE packages (
    digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),
    code text NOT NULL, version text NOT NULL,
    material bytea NOT NULL, approval bytea NOT NULL, binding bytea NOT NULL,
    ready boolean NOT NULL DEFAULT false,
    UNIQUE (code,version)
);
CREATE TABLE revocations (
    digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),
    owner_action text NOT NULL, revoked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE credentials (
    ref text PRIMARY KEY, channel text NOT NULL, code text NOT NULL,
    digest bytea NOT NULL CHECK(octet_length(digest)=32), names text[] NOT NULL, markers bytea[] NOT NULL, sealed bytea NOT NULL
);
CREATE TABLE commands (
    caller text NOT NULL, method text NOT NULL, key text NOT NULL,
    digest bytea NOT NULL CHECK(octet_length(digest)=32), response bytea,
    PRIMARY KEY(caller,method,key)
);
CREATE TABLE operations (
    exchange text PRIMARY KEY, caller text NOT NULL, key text NOT NULL, method text NOT NULL,
    digest bytea NOT NULL CHECK(octet_length(digest)=32),
    executor text REFERENCES executors(id), generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
    selected bytea REFERENCES packages(digest), callback bytea,
    requests integer NOT NULL DEFAULT 0 CHECK(requests BETWEEN 0 AND 4),
    responses integer NOT NULL DEFAULT 0 CHECK(responses BETWEEN 0 AND requests),
    steps integer NOT NULL DEFAULT 0 CHECK(steps BETWEEN 0 AND 5),
    terminal bytea, evidence bytea, evidence_hash bytea, quarantine boolean NOT NULL DEFAULT false,
    UNIQUE(caller,key),
    CHECK ((terminal IS NULL) = (evidence IS NULL)),
    CHECK ((terminal IS NULL) = (evidence_hash IS NULL)),
    CHECK (octet_length(evidence_hash)=32)
);
CREATE INDEX unfinished_operations ON operations(executor) WHERE terminal IS NULL;
CREATE TABLE attempts (
    exchange text REFERENCES operations(exchange), number integer CHECK(number BETWEEN 1 AND 4),
    request bytea NOT NULL, reception bytea, outcome text,
    PRIMARY KEY(exchange,number), CHECK((reception IS NULL)=(outcome IS NULL))
);
CREATE FUNCTION immutable_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable gateway record'; END $$;
CREATE TRIGGER permanent_revocation BEFORE UPDATE OR DELETE ON revocations FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_credentials BEFORE UPDATE OR DELETE ON credentials FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER permanent_fence BEFORE UPDATE ON executors FOR EACH ROW WHEN (OLD.fenced AND NOT NEW.fenced) EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_package BEFORE UPDATE OF digest,code,version,material,approval,binding ON packages FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_command BEFORE UPDATE ON commands FOR EACH ROW WHEN (OLD.response IS NOT NULL) EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_terminal BEFORE UPDATE ON operations FOR EACH ROW WHEN (OLD.terminal IS NOT NULL) EXECUTE FUNCTION immutable_record();
CREATE TRIGGER preserve_operation BEFORE DELETE ON operations FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_attempt BEFORE UPDATE ON attempts FOR EACH ROW WHEN (OLD.reception IS NOT NULL) EXECUTE FUNCTION immutable_record();
CREATE TRIGGER immutable_domain BEFORE UPDATE OR DELETE ON gateway_identity FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER preserve_package BEFORE DELETE ON packages FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER preserve_command BEFORE DELETE OR UPDATE OF caller,method,key,digest ON commands FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER preserve_binding BEFORE UPDATE OF exchange,caller,key,method,digest ON operations FOR EACH ROW EXECUTE FUNCTION immutable_record();
CREATE TRIGGER preserve_intent BEFORE DELETE OR UPDATE OF exchange,number,request ON attempts FOR EACH ROW EXECUTE FUNCTION immutable_record();
