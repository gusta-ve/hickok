"""Connected reverse-shell sessions and their registry."""

from __future__ import annotations

import asyncio
import sys
import time

# Cap the live replay buffer for a session with no active collector, so a chatty
# shell left at the console can't grow it without bound (chunks are ~4 KiB). The
# full stream is always on the transcript; this only bounds the in-memory tail.
_MAX_QUEUED_CHUNKS = 2048


class ShellSession:
    """One connected shell. A background task pumps inbound data either into a
    queue (so `cmd` can collect a burst of output) or straight to stdout (while
    interacting)."""

    def __init__(self, sid: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 on_close=None, log_path=None):
        self.id = sid
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername") or ("?", 0)
        self.connected = time.time()
        self.alive = True
        self.closed = asyncio.Event()  # set when the shell drops, so interact can wake on it
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._mirror = False
        self._task: asyncio.Task | None = None
        self._on_close = on_close      # called once when the shell drops on its own
        self._closing = False          # set on a deliberate kill, to skip the "died" notice
        self.log_path = log_path
        self._log = None
        if log_path:
            try:
                self._log = open(log_path, "ab", buffering=0)
            except OSError:
                self._log = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        try:
            while True:
                data = await self.reader.read(4096)
                if not data:
                    break
                if self._log is not None:
                    try:
                        self._log.write(data)
                    except OSError:
                        pass
                if self._mirror:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    # No one is collecting (sitting at the console, not interacting):
                    # keep the latest output for the next cmd/interact, but bound it —
                    # drop the oldest chunk past the cap so a noisy shell can't grow
                    # this without limit. The transcript above still has everything.
                    if self._queue.qsize() >= _MAX_QUEUED_CHUNKS:
                        try:
                            self._queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    self._queue.put_nowait(data)
        except Exception:
            pass
        finally:
            self.alive = False
            self.closed.set()
            self._close_log()
            if self._on_close and not self._closing:
                self._on_close(self)

    def _close_log(self) -> None:
        if self._log is not None:
            try:
                self._log.close()
            except OSError:
                pass
            self._log = None

    async def send(self, data: bytes) -> None:
        """Write to the shell. A dropped peer (broken pipe / connection reset) marks the
        session dead instead of raising: interact forwards keystrokes fire-and-forget, so
        an unhandled error here would surface as a task traceback and keep firing at the
        dead socket — the loop the user hit. Callers see `alive`/`closed` flip instead."""
        if not self.alive:
            return
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError):
            self.alive = False
            self.closed.set()

    async def collect(self, timeout: float = 1.0) -> bytes:
        """Drain buffered output for up to `timeout` seconds of silence."""
        chunks: list[bytes] = []
        try:
            while True:
                chunks.append(await asyncio.wait_for(self._queue.get(), timeout=timeout))
        except asyncio.TimeoutError:
            pass
        return b"".join(chunks)

    def mirror_on(self) -> None:
        # Flush whatever is queued, then stream subsequent output to stdout.
        while not self._queue.empty():
            sys.stdout.buffer.write(self._queue.get_nowait())
        sys.stdout.buffer.flush()
        self._mirror = True

    def mirror_off(self) -> None:
        self._mirror = False

    def close(self) -> None:
        self._closing = True       # deliberate: the pump shouldn't fire the "died" notice
        self.alive = False
        self.closed.set()
        self._close_log()
        try:
            self.writer.close()
        except Exception:
            pass

    @property
    def age(self) -> str:
        return f"{int(time.time() - self.connected)}s"


class SessionManager:
    def __init__(self):
        self._sessions: dict[int, ShellSession] = {}
        self._counter = 0

    def add(self, reader, writer, on_close=None, log_path=None) -> ShellSession:
        self._counter += 1
        sess = ShellSession(self._counter, reader, writer, on_close=on_close, log_path=log_path)
        self._sessions[sess.id] = sess
        return sess

    def get(self, sid: int) -> ShellSession | None:
        return self._sessions.get(sid)

    def remove(self, sid: int) -> None:
        sess = self._sessions.pop(sid, None)
        if sess:
            sess.close()

    def all(self) -> list[ShellSession]:
        return list(self._sessions.values())
