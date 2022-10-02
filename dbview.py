"""
https://github.com/mitmproxy/mitmproxy/issues/3075

This is an experiment to try using sqlite as a flow store as discussed in #3075.

My intuition is that mitmproxy will benefit the most if flows can be kept in the database
as much as possible. Instantiating a flow object will be slow and holding many of them
in memory is taxing. If mitmproxy can filter flows and page through the view without
keeping lots of flow instances in memory that would be best.

## Serialization

Cortesi proposed using protobufs as an in-database serialization format. I agree with the
idea that building a fully normalized database schema with lots of tables is not required. I wanted
to try using JSON, not protobuf, as the serialization format because that would allow us to
use sqlite's json functions to extract details from the flow in-database. This can be seen
in the flow_table sqlite view which builds the necessary details to display flows without
instantiating HTTPFlow instances in Python. As Cortesi said in the issue:

    Have the orderings stored in the database with indexes over them, and use select
    with order by and limit/offset to retrieve the data. This is simple and should be
    performant.

I'm not using a database ORM like SQLAlchemy or peewee because mitmproxy's stateobject based
classes are easily serializable. One issue is that the Python bytes data type is not supported by
JSON. I'm decoding these into Python Unicode strings and doing the inverse as required before
executing HTTPFlow.from_state().

One advantage of serializing as JSON is that sqlite indexes can be used to optimize filter
queries.

## Database Interface

I'm using the standard Python sqlite3 module. I considered using apsw but the benefits were
few and the standard library module is acceptable. apsw's pre-built wheel for OS X does not
include the regular expression support. Users would be required to install ICU and then
build apsw. This seems like a burden. I decided to add a custom SQL function, search, that
simply calls Python's re.search() function. I thought it would be slow but when I benchmarked
I was surprised that it was not horrible.

To search 1.4M header records in 100k flows:
    - SQL "LIKE '%Apple%'": 2.48 seconds
    - sqlite3 with ICU: 3.84 seconds (custom APSW build)
    - Python re.search custom SQL function: 4.38 seconds

Not bad considering LIKE won't do what mitmproxy requires and ICU requires a local build of APSW
on OSX. I'm also not certain if the ICU regex is the same as Python regex. Simple substring searches
could be implemented on the fly with LIKE and benefit from the faster processing.

The times above are even faster if each flow's headers are pre-merged into a single string. Then there
are only 100k executions of `re.search()` rather than 1.4M.

## Filters

- Translate filter specification into SQL WHERE clause.
- Add custom application functions as required to implement untranslatable searches, if required.
- Create temp views to simplify writing queries (eg. table of headers key=value for regex)
- Create indexes to accelerate filter syntax

## Flow Sorting

Standard SQL sorting should work fine for method, size, URL, and time.

## Query Optimization

Using a database gives us many options for optimizing flow filter performance:

- Indexes: Even values stored in the JSON fields can be indexed. Indexes won't help filters
  that use regular expressions, though. Since many filter syntax expressions use regular
  expressions this is a concern.
- Minimize regex evaluations. For example "~h <regex>" can be made faster by merging all headers
  into a single string ("h1=k1\nh2=k2") so that the number of `re.search()` calls is reduced. This
  combined header string could be generated on insert rather than filter evaluation.
- Cache filter results: Maintain a table of the last N filter expressions and the result. This could
  be done in Python or in the database. When a flow is added or updated to the store update the cached results.
  Caching could be implemented on full filter expressions or individual terms. Caching will likely be
  necessary for improving regex filter performance on large (~100k flows) databases.

## Migration

The core flow store schema, the chunk table, is very simple. Basically just key->value store. Maybe it never
has to change? The chunk values in the data column will be migrated on read using the normal
`mitmproxy.io.compat` code. The supporting tables, such as the `flow_table` view, would be versioned
and disposable. When mitmproxy opens a prior version database just delete all tables other than chunk
and then install whatever the current version of mitmproxy wants. Keep it simple.

If the chunk table does change this would require a true migration step.

## Copying Flows

If the user wants to save flows to a new database this could be accomplished by attaching a new database and
then creating a new chunk table in the attached database and filling it with flow chunks as selected by the user
specified filter. When complete detach the database.

## aiosqlite

There is an asyncio wrapper, aiosqlite, available for sqlite3.

## Proof-of-Concept Limitations

Limitations of this proof-of-concept:

- HTTPFlows only
- Streaming flows are stored only when concluded
- This is all ad-hoc hacks to see what works.

"""


import sqlite3
from mitmproxy import flow, http, ctx
import json
from pathlib import Path
import re

SCHEMA = Path("schema.sql").read_text()


class BytesDecoder(json.JSONEncoder):
    def default(self, flow):
        if isinstance(flow, bytes):
            return flow.decode()


def serialize(*flows):
    for flow in flows:
        if isinstance(flow, http.HTTPFlow):
            state = flow.get_state()

            # Content is stored as BLOB
            yield flow.id, "request_content", state["request"].pop("content")

            if flow.response:
                yield flow.id, "response_content", state["response"].pop("content")

            yield flow.id, "client_conn", json.dumps(
                state.pop("client_conn"), cls=BytesDecoder
            )
            yield flow.id, "server_conn", json.dumps(
                state.pop("server_conn"), cls=BytesDecoder
            )
            yield flow.id, "http_flow", json.dumps(state, cls=BytesDecoder)
        else:
            ctx.log.error(f"Did not know how to serialize {type(flow)}: {flow}")


def deserialize(*chunks):
    state = dict()
    cls = None
    for chunk in chunks:
        _, kind, data = chunk
        if kind == "http_flow":
            state.update(json.loads(data))
            if "headers" in state["request"]:
                # TODO: Implement in from_state()
                state["request"]["headers"] = [
                    [k.encode(), v.encode()] for k, v in state["request"]["headers"]
                ]
            if state["response"]:
                if "headers" in state["response"]:
                    # TODO: Implement in from_state()
                    state["response"]["headers"] = [
                        [k.encode(), v.encode()]
                        for k, v in state["response"]["headers"]
                    ]
            cls = http.HTTPFlow
        elif kind == "client_conn":
            state["client_conn"] = json.loads(data)
        elif kind == "server_conn":
            state["server_conn"] = json.loads(data)
            # TODO: Implement in from_state()
            state["server_conn"]["certificate_list"] = [
                cert.encode() for cert in state["server_conn"]["certificate_list"]
            ]
        elif kind == "request_content":
            state["request"]["content"] = data
        elif kind == "response_content":
            state["response"]["content"] = data
    return cls.from_state(state)


def store(conn, rowgen):
    with conn:
        # this is actually slower, slightly
        # conn.executemany(
        #     "INSERT OR REPLACE INTO chunk(mid, kind, data) VALUES (?, ?, ?)",
        #     list(rowgen),
        # )
        for row in rowgen:
            conn.execute(
                "INSERT OR REPLACE INTO chunk(mid, kind, data) VALUES (?, ?, ?)",
                row,
            )


def _sql_re_search(expr, string, flags=0):
    return bool(re.search(expr, string, flags=flags))


class SerializeSQLite:
    def __init__(self):
        self.connection = sqlite3.connect("dbview.db")
        # self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(SCHEMA)
        self.connection.create_function("search", 3, _sql_re_search, deterministic=True)

    def _http_events(self, data):
        if not isinstance(data, list):
            store(self.connection, serialize(data))
        else:
            for f in data:
                store(self.connection, serialize(f))
        return
        # need to deserialize reversed so that HTTPFlow state is restored first
        # then connection details and content.
        flow = deserialize(*reversed(list(serialize(data))))
        assert isinstance(flow, http.HTTPFlow)
        diffs = DeepDiff(data.get_state(), flow.get_state())
        # there are still differences where byte values are deserialized as str
        # perhaps these can be handled in the from_state() classmethod?
        if not diffs == {}:
            ctx.log.debug(diffs)

    request = _http_events
    response = _http_events
    update = _http_events
    error = _http_events


addons = [SerializeSQLite()]

NUM_FLOWS = 10_000

if __name__ == "__main__":
    from mitmproxy import io
    from itertools import cycle
    import logging
    import timeit
    import cProfile
    import pstats

    ctx.log = logging.getLogger(__name__)
    db = SerializeSQLite()

    # These pragmas are optional. They increase insert speed at the risk of
    # a flow not being recorded to "disk" when the SQL statement returns.
    # I think it is a reasonable tradeoff
    # db.connection.execute("PRAGMA synchronous = OFF;")
    # db.connection.execute("PRAGMA journal_mode = MEMORY;")
    # db.connection.execute("PRAGMA journal_mode=wal;")
    db.connection.executescript(
        """
pragma journal_mode = WAL;
pragma synchronous = off;
pragma temp_store = memory;
pragma mmap_size = 30000000000;
"""
    )

    def read_flows(flows):
        res = list()
        for _ in range(NUM_FLOWS):
            res.append(next(flows))
        return res

    def bulk_store(db, flows, count):
        numflows = 0
        for f in flows:
            store(db.connection, serialize(f))
            numflows += 1
            if numflows == count:
                break

    def bulk_store_baseline(fw, flows, count):
        numflows = 0
        for f in flows:
            fw.add(f)
            numflows += 1
            if numflows == count:
                break

    with Path("thedrive.mitm").open("rb") as f:
        thedrive = cycle(io.FlowReader(f).stream())
        testflows = read_flows(thedrive)
        # unique MID, please
        testflows = [f.copy() for f in testflows]

    # baseline
    with Path("thedrive_copy.mitm").open("wb") as f:
        fw = io.FlowWriter(f)
        print(
            f'Store {NUM_FLOWS} different flows in standard file: {timeit.timeit("bulk_store_baseline(fw, testflows, NUM_FLOWS)", globals=locals(), number=1)}'
        )

    print(
        f'Store {NUM_FLOWS} different flows in db: {timeit.timeit("bulk_store(db, testflows, NUM_FLOWS)", globals=locals(), number=1)}'
    )
    db.connection.execute("DELETE FROM chunk;")

    f = testflows[-1]
    print(f"Testing with {f.id}: {f}")
    print(
        f'Serialize {NUM_FLOWS} same chunks: {timeit.timeit("list(serialize(f))", globals=locals(), number=NUM_FLOWS)}'
    )
    chunks = list(serialize(f))
    print(
        f'Store {NUM_FLOWS} same chunks: {timeit.timeit("store(db.connection, chunks)", globals=locals(), number=NUM_FLOWS)}'
    )
    db.connection.execute("DELETE FROM chunk;")

    chunks = list(reversed(chunks))
    print(
        f'Deserialize {NUM_FLOWS} same flows: {timeit.timeit("deserialize(*chunks)", globals=locals(), number=NUM_FLOWS)}'
    )

    print(f"Store {NUM_FLOWS} different flows in db with profiling")
    pr = cProfile.Profile()
    pr.enable()
    pr.runcall(bulk_store, db, testflows, NUM_FLOWS)
    pr.disable()
    pr.dump_stats("dbview_bulk_store.pstats")
    ps = pstats.Stats(pr)
    ps.sort_stats("cumtime")
    ps.print_stats("mitmproxy|json|sqlite3")
    ps.print_callees("serialize")
    ps.print_callees("store")
