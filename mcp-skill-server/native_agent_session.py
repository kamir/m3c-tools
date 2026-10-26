"""Bounded custody of one explicitly confirmed native Go agent process."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import time

from native_agent_binding import NativeAgentBindingError
from native_agent_protocol import (
    NativeAgentProtocolError,
    parse_plan_frame,
    parse_result_frame,
    validate_confirm_token,
    validate_digest,
)


@dataclass(eq=False)
class _ClosedOutcome:
    owner: object
    possible_change: bool
    confirm_succeeded: bool


@dataclass(eq=False)
class _Session:
    owner: object
    digest: str
    deadline: float
    phase: str = "STARTING"
    observation: object = None
    spawn: object = None
    process: object = None
    plan: object = None
    readers: list = field(default_factory=list)
    frames: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=3))
    cleanup: object = None
    watchdog: object = None
    possible_change: bool = False
    confirm_succeeded: bool = False
    outcome: object = None
    stream_error: bool = False
    stdout_eof: bool = False
    stderr_eof: bool = False
    reaped: bool = False


class NativeAgentSessionHost:
    """Retain a Go journal holder; token possession is not human attestation."""

    SPAWN_SECONDS = 5
    GRACE_SECONDS = 3
    TERMINATE_SECONDS = 2
    KILL_SECONDS = 2
    READERS_SECONDS = 2
    DRAIN_SECONDS = 2
    SESSION_SECONDS = 300
    STDOUT_BYTES = 65536
    STDERR_BYTES = 16384
    READ_CHUNK = 4096

    def __init__(self, binding):
        self._binding = binding
        self._lock = asyncio.Lock()
        self._session = None
        self._last_closed = None
        self._stopped = False
        self._spawn = asyncio.create_subprocess_exec
        self._monotonic = time.monotonic

    def _failure(self, session=None, code=12, kind="unavailable"):
        messages = {
            "binding": "Native agent startup binding is unavailable; inspect operator configuration before retrying.",
            "protocol": "Native agent session output is invalid; close the session and inspect state before retrying.",
            "unavailable": "Native agent session is unavailable; close it before retrying.",
            "owner": "Native agent session belongs to another client.",
            "confirmation": "Native agent confirmation is invalid; plan a new session before retrying.",
            "io": "Native agent process operation failed; inspect state before retrying.",
            "child": "Native agent operation was denied; inspect state before retrying.",
        }
        return {
            "ok": False, "exit_code": code, "error_class": kind,
            "stderr": messages[kind],
            "possible_change": bool(session and session.possible_change),
            "remediation": "Inspect installed state and trust history before starting a new plan.",
        }

    async def plan(self, digest, owner):
        try:
            validate_digest(digest)
            if owner is None:
                return self._failure()
        except (NativeAgentProtocolError, ValueError, TypeError):
            return self._failure(kind="protocol")
        async with self._lock:
            if self._stopped or self._session is not None:
                return self._failure()
            session = _Session(owner, digest, self._monotonic() + self.SESSION_SECONDS)
            self._session = session
            self._last_closed = None
        try:
            if not self._binding.enabled:
                raise NativeAgentBindingError()
            session.observation = asyncio.create_task(asyncio.to_thread(self._binding.recheck))
            await asyncio.wait_for(asyncio.shield(session.observation), self.SPAWN_SECONDS)
            if session.phase != "STARTING":
                raise NativeAgentBindingError()
            session.spawn = asyncio.create_task(self._spawn(
                *self._binding.argv(digest), cwd=self._binding.project,
                env=self._binding.child_environment(), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                limit=self.READ_CHUNK,
            ))
            session.process = await asyncio.wait_for(
                asyncio.shield(session.spawn), self.SPAWN_SECONDS,
            )
            self._start_readers(session)
            frame = await self._frame(session)
            session.plan = parse_plan_frame(frame, self._binding, digest)
            remaining = (session.plan.expires_utc - datetime.now(timezone.utc)).total_seconds()
            session.deadline = min(session.deadline, self._monotonic() + remaining)
            if remaining <= 0 or session.stream_error:
                raise NativeAgentProtocolError()
            async with self._lock:
                if (self._session is not session or session.phase != "STARTING"
                        or session.stdout_eof or session.process.returncode is not None):
                    raise NativeAgentProtocolError()
                session.phase = "PLANNED"
            session.watchdog = asyncio.create_task(self._expire(session))
            return {"ok": True, "exit_code": 0, **session.plan.public()}
        except asyncio.CancelledError:
            await self._cancelled_cleanup(session)
            raise
        except NativeAgentBindingError:
            await self._dispose(session)
            return self._failure(session, kind="binding")
        except NativeAgentProtocolError:
            await self._dispose(session)
            return self._protocol_failure(session)
        except Exception:
            await self._dispose(session)
            return self._failure(session, code=1, kind="io")

    async def confirm(self, token, owner):
        async with self._lock:
            session = self._session
            if session is None:
                return self._failure()
            if owner is not session.owner:
                return self._failure(code=12, kind="owner")
            if session.phase != "PLANNED":
                return self._failure(session)
            session.phase = "CONFIRM_SENT"
        try:
            validate_confirm_token(token)
        except (NativeAgentProtocolError, ValueError, TypeError):
            await self._dispose(session)
            return self._failure(session, kind="confirmation")
        try:
            if self._monotonic() >= session.deadline or session.stream_error:
                raise NativeAgentProtocolError()
            # Delivery can be partial even when write/drain raises.
            session.possible_change = True
            session.process.stdin.write((token + "\n").encode("ascii"))
            await asyncio.wait_for(session.process.stdin.drain(), min(
                self.DRAIN_SECONDS, self._remaining(session),
            ))
            session.process.stdin.close()
            result = parse_result_frame(await self._frame(session), session.plan)
            # A parsed frame alone cannot establish application Close or exit success.
            extra = await self._frame(session, allow_eof=True)
            if extra is not None:
                raise NativeAgentProtocolError()
            code = await asyncio.wait_for(session.process.wait(), self._remaining(session))
            session.reaped = True
            complete = await self._dispose(session)
            if code != 0:
                return self._failure(session, code=code if code > 0 else 1, kind="child" if code > 0 else "io")
            if not complete or session.stream_error:
                return self._failure(session, code=1, kind="io")
            session.confirm_succeeded = True
            if session.outcome is not None:
                session.outcome.confirm_succeeded = True
            return {"ok": True, "exit_code": 0, **result}
        except asyncio.CancelledError:
            await self._cancelled_cleanup(session)
            raise
        except NativeAgentProtocolError:
            await self._dispose(session)
            return self._protocol_failure(session)
        except Exception:
            await self._dispose(session)
            return self._failure(session, code=1, kind="io")

    async def close(self, owner):
        async with self._lock:
            session = self._session
            previous = self._last_closed
            selected = session if session is not None else previous
            if selected is not None and owner is not selected.owner:
                return self._failure(kind="owner")
        if session is None:
            return self._closed_outcome(previous)
        try:
            if await self._dispose(session):
                return self._closed_outcome(session)
            return self._failure(session, code=1, kind="io")
        except asyncio.CancelledError:
            await self._cancelled_cleanup(session)
            raise

    async def shutdown(self):
        async with self._lock:
            self._stopped = True
            session = self._session
            previous = self._last_closed
        if session is None:
            return self._closed_outcome(previous)
        if await self._dispose(session):
            return self._closed_outcome(session)
        return self._failure(session, code=1, kind="io")

    def _closed_outcome(self, session):
        if session is not None and session.possible_change and not session.confirm_succeeded:
            return self._failure(session, code=1, kind="io")
        return {"ok": True, "exit_code": 0, "closed": True}

    def _protocol_failure(self, session):
        code = self._child_code(session)
        signalled = session.process is not None and session.process.returncode is not None and session.process.returncode < 0
        return self._failure(session, code=code or 12, kind="io" if signalled else "protocol")

    def _remaining(self, session):
        remaining = session.deadline - self._monotonic()
        if remaining <= 0:
            raise TimeoutError()
        return remaining

    @staticmethod
    def _child_code(session):
        if session.process is not None:
            code = session.process.returncode
            if isinstance(code, int) and code != 0:
                return code if code > 0 else 1
            return None
        return None

    async def _frame(self, session, allow_eof=False):
        frame = await asyncio.wait_for(session.frames.get(), self._remaining(session))
        if session.stream_error or (frame is None and not allow_eof):
            raise NativeAgentProtocolError()
        return frame

    def _start_readers(self, session):
        if not session.readers:
            session.readers = [
                asyncio.create_task(self._stdout(session)),
                asyncio.create_task(self._stderr(session)),
            ]

    async def _stdout(self, session):
        total, count = 0, 0
        pending = bytearray()
        try:
            while True:
                data = await session.process.stdout.read(self.READ_CHUNK)
                if not data:
                    if pending:
                        raise NativeAgentProtocolError()
                    session.stdout_eof = True
                    session.frames.put_nowait(None)
                    return
                total += len(data)
                if total > self.STDOUT_BYTES:
                    raise NativeAgentProtocolError()
                pending.extend(data)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    count += 1
                    if count == 2 and session.phase != "CONFIRM_SENT":
                        session.possible_change = True
                        raise NativeAgentProtocolError()
                    if count > 2:
                        raise NativeAgentProtocolError()
                    session.frames.put_nowait(bytes(line) + b"\n")
        except (Exception, asyncio.CancelledError):
            session.stream_error = True
            if not session.frames.full():
                session.frames.put_nowait(None)
            self._begin_cleanup(session)

    async def _stderr(self, session):
        total = 0
        try:
            while True:
                data = await session.process.stderr.read(self.READ_CHUNK)
                if not data:
                    session.stderr_eof = True
                    return
                total += len(data)
                if total > self.STDERR_BYTES:
                    raise NativeAgentProtocolError()
        except (Exception, asyncio.CancelledError):
            session.stream_error = True
            self._begin_cleanup(session)

    async def _expire(self, session):
        try:
            try:
                await asyncio.wait_for(session.process.wait(), self._remaining(session))
            except asyncio.TimeoutError:
                pass
            await self._dispose(session)
        except asyncio.CancelledError:
            return

    def _begin_cleanup(self, session):
        previous = session.cleanup
        retry = (previous is not None and previous.done() and not previous.cancelled()
                 and previous.exception() is None and previous.result() is False
                 and (session.observation is None or session.observation.done())
                 and (session.spawn is None or session.spawn.done()))
        if previous is None or retry:
            session.phase = "CLOSING"
            session.cleanup = asyncio.create_task(self._cleanup(session))
        return session.cleanup

    async def _dispose(self, session):
        return await asyncio.shield(self._begin_cleanup(session))

    async def _cancelled_cleanup(self, session):
        # The retained task continues if the awaiting caller is cancelled again.
        try:
            await self._dispose(session)
        except asyncio.CancelledError:
            pass

    async def _cleanup(self, session):
        if session.watchdog is not None and session.watchdog is not asyncio.current_task():
            session.watchdog.cancel()
        if session.observation is not None and not session.observation.done():
            try:
                await asyncio.wait_for(asyncio.shield(session.observation), self.SPAWN_SECONDS)
            except asyncio.TimeoutError:
                session.observation.add_done_callback(lambda task: self._late_observation(session, task))
                return False
            except Exception:
                return await self._release(session)
        if session.process is None and session.spawn is not None:
            try:
                session.process = await asyncio.wait_for(
                    asyncio.shield(session.spawn), self.SPAWN_SECONDS,
                )
            except asyncio.TimeoutError:
                session.spawn.add_done_callback(lambda task: self._late_spawn(session, task))
                return False
            except Exception:
                return await self._release(session)
        if session.process is None:
            return await self._release(session)
        self._start_readers(session)
        process = session.process
        try:
            if process.stdin is not None:
                process.stdin.close()
        except Exception:
            session.stream_error = True
        for seconds, action in (
            (self.GRACE_SECONDS, None), (self.TERMINATE_SECONDS, "terminate"),
            (self.KILL_SECONDS, "kill"),
        ):
            try:
                if action is not None and process.returncode is None:
                    getattr(process, action)()
                await asyncio.wait_for(process.wait(), seconds)
                session.reaped = True
                break
            except (Exception, asyncio.CancelledError):
                continue
        done, pending = await asyncio.wait(session.readers, timeout=self.READERS_SECONDS)
        if pending or not session.reaped:
            # Never release custody while readers or the child remain unresolved.
            return False
        for task in done:
            if task.cancelled() or task.exception() is not None:
                session.stream_error = True
        return await self._release(session)

    def _late_observation(self, session, task):
        # A completed observation never authorizes a late spawn.
        try:
            task.result()
        except (Exception, asyncio.CancelledError):
            pass
        if session.cleanup is None or session.cleanup.done():
            session.cleanup = asyncio.create_task(self._cleanup(session))

    def _late_spawn(self, session, task):
        try:
            session.process = task.result()
        except (Exception, asyncio.CancelledError):
            pass
        # Late custody resolution still cleans this generation, never starts a plan.
        if session.cleanup is None or session.cleanup.done():
            session.cleanup = asyncio.create_task(self._cleanup(session))

    async def _release(self, session):
        async with self._lock:
            if self._session is session:
                self._session = None
                # Retain only disposition, never a process, plan or token.
                session.outcome = _ClosedOutcome(
                    session.owner, session.possible_change, session.confirm_succeeded,
                )
                self._last_closed = session.outcome
        return True
