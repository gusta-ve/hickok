import re

from hickok import sqli


class _FakeOracle:
    """Answers `(expr) > n` / `(expr) >= n` for a known value, so the binary
    search can be tested without a server."""

    def __init__(self, resolver):
        self.resolver = resolver   # cond -> the integer being compared
        self.count = 0

    def ask(self, cond: str) -> bool:
        self.count += 1
        op, n = re.search(r"(>=|>)\s*(\d+)\s*$", cond).groups()
        val = self.resolver(cond)
        return val > int(n) if op == ">" else val >= int(n)


def test_extract_int_binary_search():
    o = _FakeOracle(lambda cond: 31337)
    assert sqli.extract_int(o, "whatever") == 31337


def test_extract_str_reads_each_char():
    secret = "s3cr3t!"
    prof = sqli._PROFILES["sqlite"]

    def resolver(cond):
        if "length(" in cond.lower():
            return len(secret)
        i = int(re.search(r",\s*(\d+)\s*,\s*1", cond).group(1))   # substr((q),i,1)
        return ord(secret[i - 1]) if 1 <= i <= len(secret) else 0

    assert sqli.extract_str(_FakeOracle(resolver), prof, "(SELECT password ...)") == secret


def test_profiles_cover_each_dbms_with_the_same_shape():
    keys = set(sqli._PROFILES["sqlite"])
    for name, prof in sqli._PROFILES.items():
        assert set(prof) == keys, f"{name} profile is missing keys"
    assert {"sqlite", "mysql", "mssql", "postgres"} <= set(sqli._PROFILES)
