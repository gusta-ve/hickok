import asyncio

from hickok.session import ShellSession


class _Reader:
    """A stand-in StreamReader that yields preset chunks then EOF."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, _n):
        return self._chunks.pop(0) if self._chunks else b""


class _Writer:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, _k):
        return ("1.2.3.4", 4444)

    def write(self, _d):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def test_session_logs_transcript_and_fires_on_close(tmp_path):
    """Inbound shell output is written to the transcript, and a natural drop fires
    the on_close notice."""
    log = tmp_path / "s.log"
    closed = []

    async def run():
        sess = ShellSession(1, _Reader([b"uid=0(root) ", b"gid=0\n"]), _Writer(),
                            on_close=lambda s: closed.append(s.id), log_path=str(log))
        sess.start()
        await sess._task

    asyncio.run(run())
    assert log.read_bytes() == b"uid=0(root) gid=0\n"
    assert closed == [1]                       # the shell dropped on its own → notice fires


def test_buffered_output_is_capped(monkeypatch):
    """Output piling up while no one collects (a chatty shell left at the prompt) is
    bounded — the oldest chunks drop instead of buffering forever."""
    from hickok import session

    monkeypatch.setattr(session, "_MAX_QUEUED_CHUNKS", 4)

    async def run():
        sess = ShellSession(3, _Reader([bytes([i]) for i in range(20)]), _Writer())
        sess.start()
        await sess._task
        return sess

    sess = asyncio.run(run())
    assert sess._queue.qsize() == 4            # bounded to the cap, not all 20


def test_deliberate_close_suppresses_the_died_notice():
    """A kill (close) must not fire the 'died' notice — that's reserved for shells
    that drop on their own."""
    fired = []

    async def run():
        sess = ShellSession(2, _Reader([]), _Writer(), on_close=lambda s: fired.append(s.id))
        sess.close()                           # deliberate
        sess.start()
        await sess._task

    asyncio.run(run())
    assert fired == []
