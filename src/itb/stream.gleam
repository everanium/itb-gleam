//// itb/stream — incremental stream sessions over a Pipeline.
////
//// A `Session` wraps the backend's NIF stream resource together
//// with its parent `Pipeline` value, so a live session keeps the
//// pipeline reachable on the Gleam side; the NIF resource
//// additionally pins the parent internally, so the pipeline can
//// never be collected under a live session. `free` releases
//// eagerly from any state (mid-flight, mid-error, or after a clean
//// drain); garbage collection is the release backstop.

import gleam/result
import itb/pipeline.{type Pipeline}
import itb_gleam.{type ItbError}

type SessionHandle

/// Opaque incremental stream session (encrypt or decrypt side).
pub opaque type Session {
  Session(handle: SessionHandle, parent: Pipeline)
}

@external(erlang, "itb_gleam_ffi", "encrypt_stream")
fn ffi_encrypt_stream(pipeline: Pipeline) -> Result(SessionHandle, ItbError)

@external(erlang, "itb_gleam_ffi", "decrypt_stream")
fn ffi_decrypt_stream(pipeline: Pipeline) -> Result(SessionHandle, ItbError)

@external(erlang, "itb_gleam_ffi", "stream_write")
fn ffi_stream_write(
  handle: SessionHandle,
  data: BitArray,
) -> Result(Nil, ItbError)

@external(erlang, "itb_gleam_ffi", "stream_end")
fn ffi_stream_end(handle: SessionHandle) -> Result(Nil, ItbError)

@external(erlang, "itb_gleam_ffi", "stream_read")
fn ffi_stream_read(
  handle: SessionHandle,
  max_bytes: Int,
) -> Result(#(BitArray, Bool), ItbError)

@external(erlang, "itb_gleam_ffi", "stream_free")
fn ffi_stream_free(handle: SessionHandle) -> Nil

/// Opens an incremental encrypt session (plaintext in, wire out).
pub fn encrypt(pipeline: Pipeline) -> Result(Session, ItbError) {
  ffi_encrypt_stream(pipeline)
  |> result.map(Session(_, pipeline))
}

/// Receive-side counterpart (wire in, plaintext out).
pub fn decrypt(pipeline: Pipeline) -> Result(Session, ItbError) {
  ffi_decrypt_stream(pipeline)
  |> result.map(Session(_, pipeline))
}

/// Feeds `data` into the session. Blocks (on a dirty scheduler)
/// until the cipher chain accepts the bytes; errors are sticky.
pub fn write(session: Session, data: BitArray) -> Result(Nil, ItbError) {
  ffi_stream_write(session.handle, data)
}

/// Signals end-of-input. Idempotent; a write after end fails with
/// status "bad_input".
pub fn finish(session: Session) -> Result(Nil, ItbError) {
  ffi_stream_end(session.handle)
}

/// Drains up to `max_bytes` produced bytes. Returns
/// `#(data, finished)` — `data` may be `<<>>` when nothing is
/// currently available, and `finished` is `True` once the session
/// has ended AND the output is fully drained. Partial drains are the
/// normal mode. After `finish`, an empty-spool read blocks until the
/// terminal bytes arrive or the session errors.
pub fn read(
  session: Session,
  max_bytes: Int,
) -> Result(#(BitArray, Bool), ItbError) {
  ffi_stream_read(session.handle, max_bytes)
}

/// Cancels (if still running) and eagerly releases the session.
/// Safe from any state; idempotent. Garbage collection is the
/// release backstop.
pub fn free(session: Session) -> Nil {
  ffi_stream_free(session.handle)
}

/// The parent Pipeline the session was opened on.
pub fn parent(session: Session) -> Pipeline {
  session.parent
}
