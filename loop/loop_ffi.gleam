//// The typed declarations of the BEAM primitives the utility reaches
//// through `loop_native_ffi.erl`: process creation and messaging, the
//// ref-based request / reply the lock uses, atomic counters, the
//// monotonic clock, single-write output, the environment,
//// fixed-decimal float rendering, timers and process exit.
////
//// Gleam-specific. Gleam's standard library exposes none of these,
//// and this binding depends on `gleam_stdlib` alone; the established
//// mechanism for reaching a BEAM facility Gleam lacks is an Erlang
//// adapter module, which the binding already carries for its bench
//// and eitb programs. Nothing here touches libitb3: every ITB call
//// the utility makes goes through the binding's own Gleam surface.

/// Opaque process identifier.
pub type Pid

/// Opaque reference used to match one request to its reply.
pub type Ref

/// Opaque atomics word; slot 1 carries the run's stop request.
pub type Flags

/// Opaque counters array; slots 1 and 2 carry the rekey and
/// blob-cycle totals.
pub type Counts

/// Opaque timer reference.
pub type Timer

@external(erlang, "loop_native_ffi", "self_pid")
pub fn self_pid() -> Pid

@external(erlang, "loop_native_ffi", "spawn_fn")
pub fn spawn_fn(body: fn() -> Nil) -> Pid

/// Turns an abnormal exit of `pid` into the message `make_msg`
/// builds, delivered to `parent`. A normal exit sends nothing.
@external(erlang, "loop_native_ffi", "watch_process")
pub fn watch_process(
  pid: Pid,
  parent: Pid,
  make_msg: fn(Pid, String) -> msg,
) -> Nil

@external(erlang, "loop_native_ffi", "send")
pub fn send(pid: Pid, msg: msg) -> Nil

/// Unconditional receive: every message a loop process is sent is one
/// of its own message values, so no selection is needed.
@external(erlang, "loop_native_ffi", "receive_any")
pub fn receive_any() -> msg

/// Ref-based request / reply. The caller may have unrelated messages
/// queued, so the reply is matched on the reference rather than taken
/// from the front of the queue.
@external(erlang, "loop_native_ffi", "call")
pub fn call(pid: Pid, make_request: fn(Pid, Ref) -> msg) -> reply

@external(erlang, "loop_native_ffi", "reply")
pub fn reply(pid: Pid, ref: Ref, value: value) -> Nil

@external(erlang, "loop_native_ffi", "atomics_new")
pub fn atomics_new(slots: Int) -> Flags

@external(erlang, "loop_native_ffi", "atomics_put")
pub fn atomics_put(flags: Flags, slot: Int, value: Int) -> Nil

@external(erlang, "loop_native_ffi", "atomics_get")
pub fn atomics_get(flags: Flags, slot: Int) -> Int

@external(erlang, "loop_native_ffi", "counters_new")
pub fn counters_new(slots: Int) -> Counts

@external(erlang, "loop_native_ffi", "counters_add")
pub fn counters_add(counts: Counts, slot: Int, incr: Int) -> Nil

@external(erlang, "loop_native_ffi", "counters_get")
pub fn counters_get(counts: Counts, slot: Int) -> Int

@external(erlang, "loop_native_ffi", "monotonic_ns")
pub fn monotonic_ns() -> Int

/// One io request per line, so a line and its newline can never be
/// separated by another worker's line.
@external(erlang, "loop_native_ffi", "write_stdout")
pub fn write_stdout(text: String) -> Nil

@external(erlang, "loop_native_ffi", "write_stderr")
pub fn write_stderr(text: String) -> Nil

@external(erlang, "loop_native_ffi", "getenv")
pub fn getenv(name: String) -> Result(String, Nil)

/// The whole contents of a file as text; `Error(Nil)` when it cannot
/// be read.
@external(erlang, "loop_native_ffi", "read_text")
pub fn read_text(path: String) -> Result(String, Nil)

@external(erlang, "loop_native_ffi", "halt")
pub fn halt(code: Int) -> Nil

/// A float with a fixed number of decimals, never in exponent form.
@external(erlang, "loop_native_ffi", "format_float")
pub fn format_float(value: Float, decimals: Int) -> String

@external(erlang, "loop_native_ffi", "send_after")
pub fn send_after(millis: Int, pid: Pid, msg: msg) -> Timer

@external(erlang, "loop_native_ffi", "cancel_timer")
pub fn cancel_timer(timer: Timer) -> Nil

@external(erlang, "loop_native_ffi", "random_bytes")
pub fn random_bytes(n: Int) -> BitArray

/// Length of the longest common prefix of two byte strings — the
/// offset of their first difference.
@external(erlang, "loop_native_ffi", "common_prefix")
pub fn common_prefix(a: BitArray, b: BitArray) -> Int

@external(erlang, "loop_native_ffi", "hex_lower")
pub fn hex_lower(bytes: BitArray) -> String

@external(erlang, "loop_native_ffi", "argv")
pub fn argv() -> List(String)

/// Installs the termination-signal handler that sets the stop slot.
@external(erlang, "loop_native_ffi", "install_signal_handler")
pub fn install_signal_handler(flags: Flags) -> Nil

/// Installs the logger filter that keeps the emulator's own report
/// about a closed stdout pipe off stderr, so the closed-consumer exit
/// prints nothing.
@external(erlang, "loop_native_ffi", "install_closed_pipe_filter")
pub fn install_closed_pipe_filter() -> Nil
