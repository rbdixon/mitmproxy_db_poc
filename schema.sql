DROP TABLE IF EXISTS "chunk";

CREATE TABLE IF NOT EXISTS "chunk" (
    "id" INTEGER PRIMARY KEY,
    "mid" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    -- add version field so function results can be cached?
    "seq" INTEGER DEFAULT 0,
    -- sqlite is not strongly typed so we can dump
    -- binary, JSON, whatever in here
    "data" BLOB,
    -- Could also extract on write
    "method" TEXT AS (
        CASE
            WHEN kind = "http_flow" THEN json_extract(data, "$.request.method")
            ELSE ""
        END
    ) STORED
);

DROP INDEX IF EXISTS kind_idx;

CREATE INDEX kind_idx ON chunk(kind);

DROP INDEX IF EXISTS mid_idx;

CREATE INDEX mid_idx ON chunk(mid);

DROP INDEX IF EXISTS cond_mid_kind_idx;

CREATE UNIQUE INDEX cond_mid_kind_idx ON chunk(mid, kind)
WHERE
    kind NOT IN ("asdasd");

DROP TRIGGER IF EXISTS inc_mid_seq;

CREATE TRIGGER inc_mid_seq
AFTER
INSERT
    ON chunk BEGIN
UPDATE
    chunk
SET
    seq = (
        SELECT
            max(seq)
        FROM
            chunk
        WHERE
            mid = new.mid
    ) + 1
WHERE
    id = new.id;

END;

DROP VIEW IF EXISTS flow_table;

-- The idea is that the view generates only what is required to display the flow
-- view in mitmproxy. This avoids the overhead of having to instantiate Flow objects.
-- TODO: This would be a "CREATE TEMP VIEW"
CREATE VIEW flow_table(
    mid,
    timestamp_created,
    method,
    host,
    path,
    status_code,
    content_type,
    duration,
    size
) AS
SELECT
    mid,
    json_extract(data, "$.timestamp_created"),
    json_extract(data, "$.request.method"),
    json_extract(data, "$.request.host"),
    json_extract(data, "$.request.path"),
    -- extract status code
    CAST(
        json_extract(data, "$.response.status_code") AS INTEGER
    ),
    -- extract content type
    (
        SELECT
            CASE
                WHEN pos = 0 THEN ct
                ELSE substr(ct, 1, pos - 1)
            END
        FROM
            (
                SELECT
                    json_extract(header.value, "$[1]") AS ct,
                    instr(json_extract(header.value, "$[1]"), ';') AS pos
                FROM
                    chunk AS c2,
                    json_each(data, "$.response.headers") AS header
                WHERE
                    c2.mid = chunk.mid
                    AND c2.kind = "http_flow"
                    AND lower(json_extract(header.value, "$[0]")) = "content-type"
            )
    ),
    -- calculate duration
    json_extract(data, "$.response.timestamp_end") - json_extract(data, "$.response.timestamp_start"),
    -- extract and calculate size
    (
        SELECT
            sum(length(c2.data))
        FROM
            chunk AS c2
        WHERE
            c2.mid = chunk.mid
            AND c2.kind IN ("request_content", "response_content")
    )
FROM
    chunk
WHERE
    kind = "http_flow";

DROP VIEW IF EXISTS header;

CREATE VIEW header(mid, k, v, kvstr) AS
SELECT
    mid,
    json_extract(h.value, "$[0]"),
    json_extract(h.value, "$[1]"),
    json_extract(h.value, "$[0]") || "=" || json_extract(h.value, "$[1]")
FROM
    chunk,
    -- TODO: response headers
    json_each(data, "$.request.headers") AS h
WHERE
    kind = "http_flow";

-- CREATE TABLE hmany AS
-- SELECT
--     mid,
--     json_extract(h.value, "$[0]") AS k,
--     json_extract(h.value, "$[1]") AS v,
--     json_extract(h.value, "$[0]") || "=" || json_extract(h.value, "$[1]") AS kv
-- FROM
--     chunk,
--     -- TODO: response headers
--     json_each(data, "$.request.headers") AS h
-- WHERE
--     kind = "http_flow";
-- CREATE TABLE hgroup AS
-- SELECT
--     mid,
--     GROUP_CONCAT(kv, '\n') AS headers
-- FROM
--     (
--         SELECT
--             mid,
--             json_extract(h.value, "$[0]") || "=" || json_extract(h.value, "$[1]") AS kv
--         FROM
--             chunk
--             CROSS JOIN json_each(data, "$.request.headers") AS h
--         WHERE
--             kind = "http_flow"
--     )
-- GROUP BY
--     mid;
-- CREATE VIEW headers(mid, headers) AS
-- SELECT
--     mid,
--     GROUP_CONCAT(kv, '\n') AS headers
-- FROM
--     (
--         SELECT
--             mid,
--             json_extract(h.value, "$[0]") || "=" || json_extract(h.value, "$[1]") AS kv
--         FROM
--             chunk
--             CROSS JOIN json_each(data, "$.request.headers") AS h
--         WHERE
--             kind = "http_flow"
-- );
DROP INDEX IF EXISTS idx_method;

-- Learning: minimize number of trips across sqlite<->python boundary
-- Learning: materialized tables search faster, of course
-- In [1]: %time len(conn.execute('select mid from hmany where kv LIKE "%dest=empty"').fetchall())
-- CPU times: user 241 ms, sys: 56.8 ms, total: 298 ms
-- Wall time: 299 ms
-- Out[1]: 21821
-- In [2]: %time len(conn.execute('select mid from header where kvstr LIKE "%dest=empty"').fetchall())
-- CPU times: user 2.39 s, sys: 141 ms, total: 2.54 s
-- Wall time: 2.55 s
-- Out[2]: 21821
-- In [4]: %time len(conn.execute('select mid from hgroup where headers LIKE "%dest=empty"').fetchall())
-- CPU times: user 76.9 ms, sys: 22.4 ms, total: 99.3 ms
-- Wall time: 98.9 ms
-- In [6]: %time len(conn.execute('select mid from hmany where search("dest=empty", kv, 0)').fetchall())
-- CPU times: user 1.74 s, sys: 65.8 ms, total: 1.8 s
-- Wall time: 1.82 s
-- Out[6]: 19392
-- In [7]: %time len(conn.execute('select mid from header where search("dest=empty", kvstr, 0)').fetchall())
-- CPU times: user 4.24 s, sys: 223 ms, total: 4.47 s
-- Wall time: 4.49 s
-- Out[7]: 19392
-- In [8]: %time len(conn.execute('select mid from hgroup where search("dest=empty", headers, 0)').fetchall())
-- CPU times: user 221 ms, sys: 27.7 ms, total: 249 ms
-- Wall time: 257 ms
-- Out[8]: 19392
CREATE INDEX idx_method ON chunk(UPPER(json_extract(data, "$.request.method")))
WHERE
    kind = 'http_flow';