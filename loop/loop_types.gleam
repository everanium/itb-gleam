//// The vocabulary every unit shares: the resolved configuration, the
//// per-worker result, the run handle, the cipher surfaces and payload
//// modes, and the prefixed output both the maintenance and the
//// summary units emit.
////
//// Gleam-specific. Gleam forbids a circular import, and the
//// maintenance and summary units both log while the launcher depends
//// on both; a declarations unit holding what every side needs is how
//// the cycle is broken. Everything here is vocabulary — no policy,
//// no ITB call.

import gleam/int
import gleam/string
import itb3_gleam
import loop_ffi.{type Counts, type Flags, type Pid}

/// --goroutines ceiling; the harness targets modest hosts and each
/// worker pins a payload-sized buffer for the whole run.
pub const max_workers = 10

/// The concurrency mode this binding implements, as the summary
/// reports it (shared-handle / independent-handles / single).
pub const concurrency = "shared-handle"

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
pub const pump_slice = 1_048_576

/// Profiles the shape-based pair is built against when --profile is
/// empty.
pub const default_stream_profile = "streaming-aead-triple-mac-v1"

pub const default_message_profile = "singlemsg-triple-mac-v1"

/// The primitive supplied for the parallax palette and the outer
/// cipher when a profile leaves them unnamed.
pub const keystream_fill_cipher = "aescmac"

/// Cipher surfaces the --shape flag selects.
pub type Shape {
  Stream
  Message
  StreamOneShot
  Both
}

/// Plaintext content policies the --payload-mode flag selects.
pub type PayloadMode {
  Fixed
  Rotating
  PatternZero
  PatternFf
  PatternAscii
}

/// The resolved command line.
pub type Config {
  Config(
    duration_ns: Int,
    iterations: Int,
    workers_requested: Int,
    workers: Int,
    shape: Shape,
    hash: String,
    mac: String,
    payload: Int,
    memlimit: Int,
    memlimit_auto: Bool,
    gogc: Int,
    parallax: Bool,
    wrapper: Bool,
    profile: String,
    key_bits: Int,
    nonce_bits: Int,
    blob_mode: Int,
    chunk_size: Int,
    barrier_fill: Int,
    drbg: String,
    gomaxprocs: Int,
    rekey_every: Int,
    blob_cycle_every: Int,
    payload_mode: PayloadMode,
    seed: Int,
    json_output: Bool,
    memprofile: String,
  )
}

/// What one worker hands back when it returns: its counters, the
/// instant it finished, and the error it stopped on.
pub type WStats {
  WStats(
    id: Int,
    iters: Int,
    bytes_enc: Int,
    bytes_dec: Int,
    nanos_enc: Int,
    nanos_dec: Int,
    finish_ns: Int,
    failed: Bool,
    error: String,
  )
}

/// The run handle every worker carries: the resolved configuration,
/// the pid of the state process that owns the Pipeline handles and
/// the lock, the atomics word holding the stop request, the counters
/// array behind the rekey and blob-cycle totals, and the two profile
/// names the log lines quote.
pub type Run {
  Run(
    cfg: Config,
    state: Pid,
    flags: Flags,
    counts: Counts,
    stream_profile: String,
    msg_profile: String,
  )
}

pub fn shape_name(shape: Shape) -> String {
  case shape {
    Stream -> "stream"
    Message -> "message"
    StreamOneShot -> "stream_one_shot"
    Both -> "both"
  }
}

pub fn parse_shape(text: String) -> Result(Shape, Nil) {
  case text {
    "stream" -> Ok(Stream)
    "message" -> Ok(Message)
    "stream_one_shot" -> Ok(StreamOneShot)
    "both" -> Ok(Both)
    _ -> Error(Nil)
  }
}

pub fn on_off(flag: Bool) -> String {
  case flag {
    True -> "on"
    False -> "off"
  }
}

pub fn bool_text(flag: Bool) -> String {
  case flag {
    True -> "true"
    False -> "false"
  }
}

/// Prints one prefixed status line to stdout.
///
/// Gleam-specific. The line and its newline are handed to the io
/// server as one request: workers log concurrently during
/// maintenance, and a routine that emitted the text and the newline
/// as two requests would let another worker's line land between them.
pub fn log(text: String) -> Nil {
  loop_ffi.write_stdout("[loop] " <> text <> "\n")
}

pub fn err(text: String) -> Nil {
  loop_ffi.write_stderr("loop: " <> text <> "\n")
}

/// `status <code>: <sentence>` — the numeric code the binding
/// resolves from the status the failing call returned, and the
/// diagnostic that call left behind, with nothing composed on this
/// side of the boundary. The sentence is taken whole however long it
/// is: the binding hands it over as a value the runtime owns, so no
/// buffer bounds it here.
pub fn status_text(status: String, detail: String) -> String {
  "status " <> int.to_string(itb3_gleam.status_code(status)) <> ": " <> detail
}

/// Renders an encoder policy env value for the summary: the raw
/// string when set, "default" when the shipped ladder applies.
pub fn policy_label(name: String) -> String {
  case loop_ffi.getenv(name) {
    Error(Nil) -> "default"
    Ok(value) ->
      case string.trim_start(value) {
        "" -> "default"
        trimmed -> trimmed
      }
  }
}

pub fn to_string(n: Int) -> String {
  int.to_string(n)
}
