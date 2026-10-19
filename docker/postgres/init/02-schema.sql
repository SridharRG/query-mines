-- Sample "school assessments" schema used to exercise the optimizer.
-- Several indexes are deliberately missing, partial, duplicated or unused.

CREATE TABLE schools (
    id          bigint PRIMARY KEY,
    name        text NOT NULL,
    district    text NOT NULL,
    state       char(2) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE academic_years (
    id         bigint PRIMARY KEY,
    label      text NOT NULL,
    starts_on  date NOT NULL,
    ends_on    date NOT NULL
);

CREATE TABLE master_combined_tests (
    id       bigint PRIMARY KEY,
    name     text NOT NULL,
    subject  text NOT NULL
);

CREATE TABLE students (
    id          bigint PRIMARY KEY,
    school_id   bigint NOT NULL REFERENCES schools(id),
    first_name  text NOT NULL,
    last_name   text NOT NULL,
    email       text NOT NULL,
    grade       smallint NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL
);

CREATE TABLE test_results (
    id                       bigint PRIMARY KEY,
    student_id               bigint NOT NULL REFERENCES students(id),
    school_id                bigint NOT NULL REFERENCES schools(id),
    master_combined_test_id  bigint NOT NULL REFERENCES master_combined_tests(id),
    academic_year_id         bigint NOT NULL REFERENCES academic_years(id),
    status                   text NOT NULL,
    score                    numeric(5,2),
    taken_at                 timestamptz NOT NULL,
    created_at               timestamptz NOT NULL
);

CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    actor_id    bigint,
    action      text NOT NULL,
    payload     text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schools
SELECT g,
       'School ' || g,
       'District ' || (g % 120),
       (ARRAY['CA','TX','NY','FL','WA','IL','GA','OH'])[1 + g % 8],
       now() - (g || ' days')::interval
FROM generate_series(1, 2500) g;
-- The school id from the spec example.
INSERT INTO schools VALUES (1836876, 'Spec Example High', 'District 7', 'CA', now());

INSERT INTO academic_years VALUES
  (5132, '2023-24', '2023-08-01', '2024-06-30'),
  (5554, '2024-25', '2024-08-01', '2025-06-30'),
  (5901, '2025-26', '2025-08-01', '2026-06-30'),
  (4870, '2022-23', '2022-08-01', '2023-06-30');

INSERT INTO master_combined_tests
SELECT g, 'Combined Test ' || g, (ARRAY['math','reading','science','writing'])[1 + g % 4]
FROM generate_series(1, 60) g;

INSERT INTO students
SELECT g,
       CASE WHEN g % 50 = 0 THEN 1836876 ELSE 1 + (g % 2500) END,
       'First' || g,
       'Last' || (g % 9000),
       'student' || g || '@example.edu',
       1 + (g % 12),
       (ARRAY['active','active','active','inactive','graduated'])[1 + g % 5],
       now() - ((g % 1500) || ' days')::interval
FROM generate_series(1, 200000) g;

INSERT INTO test_results
SELECT g,
       s,
       CASE WHEN s % 50 = 0 THEN 1836876 ELSE 1 + (s % 2500) END,
       1 + (g % 60),
       (ARRAY[5132, 5554, 5901, 4870])[1 + g % 4],
       (ARRAY['active','active','archived','pending'])[1 + g % 4],
       round((random() * 100)::numeric, 2),
       timestamptz '2022-08-01' + ((g % 1400) || ' days')::interval,
       timestamptz '2022-08-01' + ((g % 1400) || ' days')::interval
FROM (SELECT g, 1 + (g % 200000) AS s FROM generate_series(1, 800000) g) t;

INSERT INTO audit_events (actor_id, action, payload, created_at)
SELECT g % 5000,
       (ARRAY['login','logout','grade.update','profile.update','export'])[1 + g % 5],
       'event payload ' || md5(g::text),
       now() - ((g % 400) || ' hours')::interval
FROM generate_series(1, 150000) g;

-- Existing indexes: a narrow one the advisor should extend, a duplicate pair,
-- and one nobody uses.
CREATE INDEX idx_test_results_school ON test_results (school_id);
CREATE INDEX idx_students_email ON students (email);
CREATE INDEX idx_students_email_copy ON students (email);
CREATE INDEX idx_audit_events_payload ON audit_events (payload);

-- Leave audit_events without autovacuum and churn it so the vacuum monitor has data.
ALTER TABLE audit_events SET (autovacuum_enabled = false);
UPDATE audit_events SET payload = payload || ' (edited)' WHERE id % 3 = 0;
DELETE FROM audit_events WHERE id % 7 = 0;

ANALYZE;
