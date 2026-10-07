//// The worker: its process body (one warmup iteration, the warmup
//// barrier, the main loop), one iteration, the session pump loop the
//// stream shape drives, and the round-trip comparison that decides
//// between a worker error and a data mismatch.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import itb3/pipeline.{type Pipeline}
import itb3/stream.{type Session}
import itb3_gleam.{type ItbError, ItbError}
import loop_ffi.{type Pid}
import loop_ops
import loop_payload
import loop_size
import loop_state
import loop_types.{
  type Run, type Shape, type WStats, Both, Message, Rotating, Stream,
  StreamOneShot, WStats,
}

/// A worker's message to the launcher.
pub type WorkerMsg {
  WarmupDone(pid: Pid)
  WorkerDone(pid: Pid, stats: WStats)
  WorkerDied(pid: Pid, reason: String)
  Deadline
}

/// The only message a worker itself receives.
pub type Release {
  Release
}

type W {
  W(
    id: Int,
    run: Run,
    plaintext: BitArray,
    seeded: Bool,
    rng: Int,
    iters: Int,
    bytes_enc: Int,
    bytes_dec: Int,
    nanos_enc: Int,
    nanos_dec: Int,
    failed: Bool,
    error: String,
  )
}

// A failing call names the entry that failed and the status it
// returned; `Same` means the entry is the direction itself, so the
// error text carries the direction once rather than twice.
type CallFailure {
  CallFailure(what: Option(String), error: ItbError)
}

/// Concurrency mode. This binding runs shared-handle: BEAM processes
/// call the NIF beneath the Gleam wrapper concurrently on dirty
/// schedulers, and one Pipeline handle serves all of them, which the
/// shared library permits after construction. `--goroutines` is
/// therefore the process count verbatim and is never clamped. The
/// handles are not captured here: every iteration receives them with
/// its read-lock grant, because a blob reopen replaces them mid-run.
pub fn start(run: Run, id: Int, plaintext: BitArray, parent: Pid) -> Pid {
  let w =
    W(
      id: id,
      run: run,
      plaintext: plaintext,
      seeded: run.cfg.seed != 0,
      rng: loop_payload.seed_worker(run.cfg.seed, id),
      iters: 0,
      bytes_enc: 0,
      bytes_dec: 0,
      nanos_enc: 0,
      nanos_dec: 0,
      failed: False,
      error: "",
    )
  loop_ffi.spawn_fn(fn() { body(w, parent) })
}

// The worker process body: one warmup iteration, the warmup barrier,
// then the main loop until a stop is requested or the fixed
// per-worker iteration budget (warmup included) is spent. A failing
// warmup still passes both barriers so the launcher never waits on a
// worker that has already given up.
fn body(w0: W, parent: Pid) -> Nil {
  // Warmup iteration — counted in the totals; its completion feeds
  // the post-warmup baselines.
  let w1 = iterate(w0, 0)
  loop_ffi.send(parent, WarmupDone(loop_ffi.self_pid()))
  let Release = loop_ffi.receive_any()
  let w2 = case w1.failed {
    True -> w1
    False -> main_loop(w1, 1)
  }
  loop_ffi.send(
    parent,
    WorkerDone(loop_ffi.self_pid(), stats(w2, loop_size.now_ns())),
  )
}

fn main_loop(w: W, iter: Int) -> W {
  let budget = w.run.cfg.iterations
  case
    { budget > 0 && iter >= budget } || loop_state.stop_requested(w.run.flags)
  {
    True -> w
    False -> {
      let w1 = iterate(w, iter)
      case w1.failed {
        True -> w1
        False ->
          case loop_ops.maintenance(w.run, w1.id, iter) {
            Ok(Nil) -> main_loop(w1, iter + 1)
            Error(text) -> fail(w1, text)
          }
      }
    }
  }
}

fn stats(w: W, finish_ns: Int) -> WStats {
  WStats(
    id: w.id,
    iters: w.iters,
    bytes_enc: w.bytes_enc,
    bytes_dec: w.bytes_dec,
    nanos_enc: w.nanos_enc,
    nanos_dec: w.nanos_dec,
    finish_ns: finish_ns,
    failed: w.failed,
    error: w.error,
  )
}

// Records the worker's error text (first error wins) and requests a
// stop of the whole run.
fn fail(w: W, text: String) -> W {
  loop_state.request_stop(w.run.flags)
  case w.failed {
    True -> w
    False -> W(..w, failed: True, error: text)
  }
}

// ------------------------------------------------------------------
// One iteration
// ------------------------------------------------------------------

// One iteration. In order: refill the plaintext under rotating mode;
// take the read lock; pick the surface; encrypt (timed); decrypt
// (timed); compare the round-trip with the plaintext; bump the
// counters; release the lock. The whole round-trip runs under the
// read lock so handle-mutating maintenance (rekey, blob reopen) never
// lands between an encrypt and its matching decrypt — maintenance
// runs after this returns, from the worker loop. The handles arrive
// with the grant rather than from the worker's own state, because a
// blob reopen swaps them. A worker that dies mid-iteration never
// releases the lock itself; the watcher on it tells the lock process,
// which drops the claim.
fn iterate(w0: W, iter: Int) -> W {
  let w = refill(w0)
  let grant = loop_state.read_lock(w.run.state)
  let result = round_trip(w, iter, grant.stream_pipe, grant.msg_pipe)
  loop_state.read_unlock(w.run.state)
  case result {
    Ok(w1) -> w1
    Error(text) -> fail(w, text)
  }
}

fn refill(w: W) -> W {
  case w.run.cfg.payload_mode {
    Rotating -> {
      let #(buf, rng) =
        loop_payload.fill(
          Rotating,
          w.seeded,
          w.rng,
          bit_array.byte_size(w.plaintext),
        )
      W(..w, plaintext: buf, rng: rng)
    }
    _ -> w
  }
}

fn round_trip(
  w: W,
  iter: Int,
  stream_pipe: Option(Pipeline),
  msg_pipe: Option(Pipeline),
) -> Result(W, String) {
  let shape = select_shape(w.run.cfg.shape, iter)
  let plain = w.plaintext
  case do_encrypt(shape, stream_pipe, msg_pipe, plain) {
    Error(f) -> Error(cipher_error(w, iter, shape, "encrypt", f))
    Ok(#(wire, enc_ns)) ->
      case do_decrypt(shape, stream_pipe, msg_pipe, wire) {
        Error(f) -> Error(cipher_error(w, iter, shape, "decrypt", f))
        Ok(#(got, dec_ns)) -> {
          compare(w, iter, shape, plain, got)
          Ok(
            W(
              ..w,
              iters: w.iters + 1,
              bytes_enc: w.bytes_enc + bit_array.byte_size(plain),
              bytes_dec: w.bytes_dec + bit_array.byte_size(got),
              nanos_enc: w.nanos_enc + enc_ns,
              nanos_dec: w.nanos_dec + dec_ns,
            ),
          )
        }
      }
  }
}

/// Shape dispatch. `message` is one whole-buffer call on the Single
/// Message Pipeline; `stream_one_shot` is one whole-buffer call on
/// the streaming Pipeline (the C ABI's `ITB_Triple_EncryptStream`,
/// which routes to the same one-shot stream entry the Go harness
/// calls by name); `stream` opens a session on the same streaming
/// Pipeline and drives the chunk loop from here. Under `both` the
/// three rotate by iteration number so the session path and the
/// whole-buffer path alternate on one handle inside every worker —
/// the cross-path state-reuse hazard this harness exists to catch.
fn select_shape(shape: Shape, iter: Int) -> Shape {
  case shape {
    Both ->
      case iter % 3 {
        0 -> Stream
        1 -> Message
        _ -> StreamOneShot
      }
    other -> other
  }
}

fn do_encrypt(
  shape: Shape,
  stream_pipe: Option(Pipeline),
  msg_pipe: Option(Pipeline),
  plain: BitArray,
) -> Result(#(BitArray, Int), CallFailure) {
  case shape {
    Stream -> timed(fn() { pump(stream_pipe, True, plain) })
    StreamOneShot ->
      timed(fn() {
        one_call(with_pipe(stream_pipe, fn(p) {
          pipeline.encrypt_stream_one_shot(p, plain)
        }))
      })
    _ ->
      timed(fn() {
        one_call(with_pipe(msg_pipe, fn(p) {
          pipeline.encrypt_message(p, plain)
        }))
      })
  }
}

fn do_decrypt(
  shape: Shape,
  stream_pipe: Option(Pipeline),
  msg_pipe: Option(Pipeline),
  wire: BitArray,
) -> Result(#(BitArray, Int), CallFailure) {
  case shape {
    Stream -> timed(fn() { pump(stream_pipe, False, wire) })
    StreamOneShot ->
      timed(fn() {
        one_call(with_pipe(stream_pipe, fn(p) {
          pipeline.decrypt_stream_one_shot(p, wire)
        }))
      })
    _ ->
      timed(fn() {
        one_call(with_pipe(msg_pipe, fn(p) {
          pipeline.decrypt_message(p, wire)
        }))
      })
  }
}

// The shape selection guarantees the Pipeline it names was built, so
// an absent handle is a defect of this utility rather than a library
// failure; it is reported as one rather than silently skipped.
fn with_pipe(
  pipe: Option(Pipeline),
  call: fn(Pipeline) -> Result(BitArray, ItbError),
) -> Result(BitArray, ItbError) {
  case pipe {
    Some(p) -> call(p)
    None -> Error(ItbError("internal", "pipeline not built for this shape"))
  }
}

fn timed(
  run_call: fn() -> Result(BitArray, CallFailure),
) -> Result(#(BitArray, Int), CallFailure) {
  let t0 = loop_size.now_ns()
  case run_call() {
    Ok(out) -> Ok(#(out, loop_size.now_ns() - t0))
    Error(f) -> Error(f)
  }
}

fn one_call(result: Result(BitArray, ItbError)) -> Result(BitArray, CallFailure) {
  case result {
    Ok(out) -> Ok(out)
    Error(e) -> Error(CallFailure(None, e))
  }
}

// ------------------------------------------------------------------
// Stream pump
// ------------------------------------------------------------------

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the binding's session
/// surface has no reader / writer entry, so the caller drives it:
/// open a session, feed slices of at most 1 MiB, drain whatever the
/// session has produced after every write (a read before end never
/// blocks), end, then drain until the session reports finished (after
/// end, a read on an empty spool blocks until the terminal bytes
/// arrive). The loop is written here rather than delegated to a
/// binding-side pump convenience so it stands in the utility, at the
/// same place, in every language.
fn pump(
  pipe: Option(Pipeline),
  encrypting: Bool,
  src: BitArray,
) -> Result(BitArray, CallFailure) {
  case pipe {
    None ->
      Error(CallFailure(
        Some("StreamBegin"),
        ItbError("internal", "pipeline not built for this shape"),
      ))
    Some(p) -> {
      let begin = case encrypting {
        True -> stream.encrypt(p)
        False -> stream.decrypt(p)
      }
      case begin {
        Error(e) -> Error(CallFailure(Some("StreamBegin"), e))
        Ok(session) -> {
          let result = feed(session, src, [])
          stream.free(session)
          result
        }
      }
    }
  }
}

fn feed(
  session: Session,
  src: BitArray,
  acc: List(BitArray),
) -> Result(BitArray, CallFailure) {
  case bit_array.byte_size(src) {
    0 ->
      case stream.finish(session) {
        Error(e) -> Error(CallFailure(Some("StreamEnd"), e))
        Ok(Nil) -> drain_final(session, acc)
      }
    size -> {
      let n = int.min(size, loop_types.pump_slice)
      case bit_array.slice(src, 0, n), bit_array.slice(src, n, size - n) {
        Ok(slice), Ok(rest) ->
          case stream.write(session, slice) {
            Error(e) -> Error(CallFailure(Some("StreamWrite"), e))
            Ok(Nil) ->
              case drain_ready(session, acc) {
                Error(f) -> Error(f)
                Ok(acc1) -> feed(session, rest, acc1)
              }
          }
        _, _ ->
          Error(CallFailure(
            Some("StreamWrite"),
            ItbError("internal", "plaintext slice out of range"),
          ))
      }
    }
  }
}

fn drain_ready(
  session: Session,
  acc: List(BitArray),
) -> Result(List(BitArray), CallFailure) {
  case stream.read(session, loop_types.pump_slice) {
    Error(e) -> Error(CallFailure(Some("StreamRead"), e))
    Ok(#(data, _finished)) ->
      case bit_array.byte_size(data) {
        0 -> Ok(acc)
        _ -> drain_ready(session, [data, ..acc])
      }
  }
}

fn drain_final(
  session: Session,
  acc: List(BitArray),
) -> Result(BitArray, CallFailure) {
  case stream.read(session, loop_types.pump_slice) {
    Error(e) -> Error(CallFailure(Some("StreamRead"), e))
    Ok(#(data, finished)) ->
      case finished {
        True -> Ok(bit_array.concat(list.reverse([data, ..acc])))
        False -> drain_final(session, [data, ..acc])
      }
  }
}

// ------------------------------------------------------------------
// Failure model
// ------------------------------------------------------------------

/// Failure model. A cipher call that returns a non-OK status is a
/// worker error: it is recorded, the run is asked to stop, the other
/// workers finish their in-flight iteration, and the error is listed
/// in the summary with the FAIL verdict. A round-trip that returns OK
/// with different bytes is a data mismatch: the process terminates
/// here, without summary or cleanup, because the Pipeline state that
/// produced the wrong bytes is the evidence and nothing that runs
/// afterwards may touch it.
fn compare(w: W, iter: Int, shape: Shape, plain: BitArray, got: BitArray) -> Nil {
  case plain == got {
    True -> Nil
    False -> {
      let off = loop_ffi.common_prefix(plain, got)
      loop_ffi.write_stderr(
        "loop: DATA MISMATCH g"
        <> int.to_string(w.id)
        <> " iter "
        <> int.to_string(iter)
        <> " shape="
        <> loop_types.shape_name(shape)
        <> ": want "
        <> int.to_string(bit_array.byte_size(plain))
        <> " bytes, got "
        <> int.to_string(bit_array.byte_size(got))
        <> " bytes, first difference at offset "
        <> int.to_string(off)
        <> ": want "
        <> hex_window(plain, off)
        <> " got "
        <> hex_window(got, off)
        <> "\n",
      )
      loop_ffi.halt(3)
    }
  }
}

// Up to 16 bytes from `off` as lowercase hex, or "-" when the buffer
// has no bytes there.
fn hex_window(bytes: BitArray, off: Int) -> String {
  let size = bit_array.byte_size(bytes)
  case off >= size {
    True -> "-"
    False ->
      case bit_array.slice(bytes, off, int.min(16, size - off)) {
        Ok(window) -> loop_ffi.hex_lower(window)
        Error(Nil) -> "-"
      }
  }
}

fn cipher_error(
  w: W,
  iter: Int,
  shape: Shape,
  direction: String,
  failure: CallFailure,
) -> String {
  let CallFailure(what, ItbError(status, detail)) = failure
  let head =
    "g"
    <> int.to_string(w.id)
    <> " iter "
    <> int.to_string(iter)
    <> " shape="
    <> loop_types.shape_name(shape)
    <> ": "
    <> direction
    <> ": "
  case what {
    None -> head <> loop_types.status_text(status, detail)
    Some(entry) -> head <> entry <> ": " <> loop_types.status_text(status, detail)
  }
}
