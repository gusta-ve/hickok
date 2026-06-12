from hickok import sqli


def test_extract_str_survives_a_junk_oracle():
    """A noisy/unreliable oracle can make the binary search converge on a junk
    code point; extract_str must yield '?' for it, never crash on chr()."""
    class _Junk:
        def ask(self, cond):           # always "yes" → search runs up to the cap
            return True

        @property
        def count(self):
            return 0

    out = sqli.extract_str(_Junk(), sqli._PROFILES["sqlite"], "x", maxlen=8)
    assert out == "?" * 8
