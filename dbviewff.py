"""
"""

from mitmproxy.flowfilter import *
from mitmproxy.flowfilter import _Action, _Rex

# | Code      | Type    | Notes   |
# |:----------|:--------|:--------|
# | a         | _Action | Should benchmark pre-computing Action filter results vs. index |
# | all       | _Action |         |
# | b         | _Rex    |         |
# | bq        | _Rex    |         |
# | bs        | _Rex    |         |
# | c         | _Int    |         |
# | comment   | _Rex    |         |
# | d         | _Rex    |         |
# | dns       | _Action |         |
# | dst       | _Rex    |         |
# | e         | _Action |         |
# | h         | _Rex    |         |
# | hq        | _Rex    |         |
# | hs        | _Rex    |         |
# | http      | _Action |         |
# | m         | _Rex    | most uses can be uppercased and then do a simple indexed-LIKE         |
# | marked    | _Action | default is "" instead of null |
# | marker    | _Rex    |         |
# | meta      | _Rex    |         |
# | q         | _Action |         |
# | replay    | _Action |         |
# | replayq   | _Action |         |
# | replays   | _Action |         |
# | s         | _Action |         |
# | src       | _Rex    |         |
# | t         | _Rex    |         |
# | tcp       | _Action |         |
# | tq        | _Rex    |         |
# | ts        | _Rex    |         |
# | u         | _Rex    |         |
# | udp       | _Action |         |
# | websocket | _Action |         |

# indexes on json_extract are just as fast if not faster than generated columns
# if the custom Python function search() is used than it is better to generate
# a merged string (eg. "h1=v1\nk2=k2" ) and reduce the number of calls out to Python land.

# monkeypatching just for proof of concept
FMarked.where = "kind='http_flow' and json_extract(data, '$.marked') is not ''"
FMarker.where = "kind='http_flow' and search(?, json_extract(data, '$.marked'), 0)"
FCode.where = "kind='http_flow' and json_extract(data, '$.response.status_code') = ?"
FHead.where = (
    "kind='http_flow' and mid in (SELECT mid from header where search(?, kvstr, 0))"
)


def _sql_int(self):
    return (self.where, (self.num,))


def _sql_unary(self):
    return (self.where, tuple())


def _sql_regex(self):
    pat = self.re.pattern
    if isinstance(pat, bytes):
        pat = pat.decode()
    return (self.where, (pat,))


def _concat_expr_binding(items):
    exprs = list()
    bindings = list()
    for item in items:
        expr, binding = item.sql()
        exprs.append(expr)
        bindings += binding
    return exprs, tuple(bindings)


def _sql_and(self):
    assert not isinstance(self, type)
    exprs, bindings = _concat_expr_binding(self.lst)
    return (" ( " + " ) AND ( ".join(exprs) + " ) ", bindings)


def _sql_or(self):
    assert not isinstance(self, type)
    exprs, bindings = _concat_expr_binding(self.lst)
    return (" ( " + " ) OR ( ".join(exprs) + " ) ", bindings)


def _sql_not(self):
    assert not isinstance(self, type)
    expr, bindings = self.itm.sql()
    return ("NOT ( " + expr + " ) ", bindings)


FMarked.sql = _sql_unary
FMarker.sql = _sql_regex
FCode.sql = _sql_int
FHead.sql = _sql_regex
FAnd.sql = _sql_and
FOr.sql = _sql_or
FNot.sql = _sql_not

# demonstrate one filter for each type
filter_unary: Sequence[type[_Action]] = [
    FMarked,
]
filter_rex: Sequence[type[_Rex]] = [
    FHead,
    FMarker,
]
filter_int = [FCode]

def _make():
    # Order is important - multi-char expressions need to come before narrow
    # ones.
    parts = []
    for cls in filter_unary:
        f = pp.Literal(f"~{cls.code}") + pp.WordEnd()
        f.setParseAction(cls.make)
        parts.append(f)

    # This is a bit of a hack to simulate Word(pyparsing_unicode.printables),
    # which has a horrible performance with len(pyparsing.pyparsing_unicode.printables) == 1114060
    unicode_words = pp.CharsNotIn("()~'\"" + pp.ParserElement.DEFAULT_WHITE_CHARS)
    unicode_words.skipWhitespace = True
    regex = (
        unicode_words
        | pp.QuotedString('"', escChar="\\")
        | pp.QuotedString("'", escChar="\\")
    )
    for cls in filter_rex:
        f = pp.Literal(f"~{cls.code}") + pp.WordEnd() + regex.copy()
        f.setParseAction(cls.make)
        parts.append(f)

    for cls in filter_int:
        f = pp.Literal(f"~{cls.code}") + pp.WordEnd() + pp.Word(pp.nums)
        f.setParseAction(cls.make)
        parts.append(f)

    # A naked rex is a URL rex:
    f = regex.copy()
    f.setParseAction(FUrl.make)
    parts.append(f)

    atom = pp.MatchFirst(parts)
    expr = pp.infixNotation(
        atom,
        [
            (pp.Literal("!").suppress(), 1, pp.opAssoc.RIGHT, lambda x: FNot(*x)),
            (pp.Literal("&").suppress(), 2, pp.opAssoc.LEFT, lambda x: FAnd(*x)),
            (pp.Literal("|").suppress(), 2, pp.opAssoc.LEFT, lambda x: FOr(*x)),
        ],
    )
    expr = pp.OneOrMore(expr)
    # this is the only modification:
    return expr.setParseAction(lambda x: FAnd(x).sql() if len(x) != 1 else x[0].sql())


bnf = _make()

def _sql_re_search(expr, string, flags=0):
    return bool(re.search(expr, string, flags=flags))


if __name__ == "__main__":
    import sqlite3
    import cProfile
    import pstats

    conn = sqlite3.connect("dbview.db")

    # install custom SQL function
    conn.create_function("search", 3, _sql_re_search, deterministic=True)

    for flt in [
        "~marked",
        "~marker foo",
        "~c 200",
        "~marked ~c 200",
        "~marked ~c 200 | ~c 201",
        "! ~marked ~c 200",
        "~h ee",
    ]:
        expr, bindings = bnf.parseString(flt, parseAll=True)[0]
        print(f"{flt}: {expr} <- {bindings}")
        pr = cProfile.Profile()
        pr.enable()
        for row in conn.execute(f"SELECT count(*) FROM chunk WHERE {expr}", bindings):
            print(row[0])
        pr.disable()
        ps = pstats.Stats(pr)
        ps.sort_stats("cumtime")
        ps.print_stats("dbview|sqlite3")
        print("")
