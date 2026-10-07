//// Long-run stress harness. The loop utility holds one Pipeline
//// handle per exercised cipher surface for minutes, hammers it with
//// concurrent encrypt -> decrypt -> compare round-trips from N worker
//// processes, rotates the outer masters and reopens the handle from
//// its session blob on a schedule, and reports whether the process
//// survived with every byte intact. It is the Gleam binding's
//// counterpart of the Go harness under `tools/loop`: the same flags,
//// the same round structure, the same summary in both renderings.
////
//// The default shape is full production: the Streaming AEAD profile
//// with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
//// inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
//// driven through a stream session by three workers for five minutes
//// on 16 MiB plaintexts. Every worker owns a distinct
//// CSPRNG-generated plaintext held for the whole run, so any
//// cross-call state leakage inside the Pipeline surfaces as a data
//// mismatch between workers rather than cancelling out.
////
//// A failure is one of two things. A cipher, rekey or load call that
//// returns a non-OK status is a worker error: the run stops, the
//// summary lists it, the verdict is FAIL and the exit code 1. A
//// round-trip that returns without error but with different bytes is
//// a data mismatch: the process terminates on the spot with exit
//// code 3, printing the worker, the iteration and the first
//// differing offset, and no summary — the state that produced the
//// wrong bytes is the evidence. A crash inside the shared library or
//// the emulator has no exit code of its own here; surfacing it is
//// what the utility is for.
////
//// Usage:
////
////     ./loop --duration 5m --goroutines 3 --shape stream
////            --hash areion512 --mac hmac-blake3 --payload-size 16MB
////            --memlimit auto --parallax on --wrapper on
////
//// Ctrl-C triggers a graceful shutdown: in-flight iterations
//// complete, then the partial summary prints.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import itb3/pipeline.{type Pipeline}
import itb3_gleam.{ItbError}
import loop_ffi.{type Flags, type Pid}
import loop_payload
import loop_size
import loop_state
import loop_summary
import loop_types.{
  type Config, type Shape, type WStats, Both,
  Config, Message, Run, Stream, StreamOneShot, WStats,
}
import loop_worker.{Deadline, WarmupDone, WorkerDied, WorkerDone}

// ------------------------------------------------------------------
// Flags
// ------------------------------------------------------------------

/// How a flag's value is parsed, and whether the usage prints a
/// default for it.
type Kind {
  KInt
  KInt64
  KUint64
  KString
  KBool
}

/// One command-line flag: its name, the type label the usage prints,
/// the kind that governs parsing and the default suffix, and its help
/// text. Values are validated after the whole line is parsed.
type Flag {
  Flag(name: String, label: String, kind: Kind, help: String)
}

/// A parsed flag value.
type Value {
  VInt(Int)
  VString(String)
  VBool(Bool)
}

// The table is in alphabetical order, the order the usage prints.
fn flag_table() -> List(Flag) {
  [
    Flag(
      "barrier-fill",
      "int",
      KInt,
      "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
    ),
    Flag(
      "blob-cycle-every",
      "int",
      KInt64,
      "reopen each pipeline from its session blob every N iterations per worker; 0 = never",
    ),
    Flag(
      "blob-mode",
      "int",
      KInt,
      "container floor sizing mode: 1 (per-region, default) | 2 (per-container)",
    ),
    Flag(
      "chunk-size",
      "string",
      KString,
      "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape",
    ),
    Flag(
      "drbg",
      "string",
      KString,
      "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)",
    ),
    Flag(
      "duration",
      "duration",
      KString,
      "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
    ),
    Flag(
      "gogc",
      "int",
      KInt,
      "GC trigger percentage; 0 = leave the runtime default",
    ),
    Flag(
      "gomaxprocs",
      "int",
      KInt,
      "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
    ),
    Flag(
      "goroutines",
      "int",
      KInt,
      "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1",
    ),
    Flag("hash", "string", KString, "inner ITB hash primitive name"),
    Flag(
      "iterations",
      "int",
      KInt64,
      "fixed per-worker iteration count; 0 = duration-based",
    ),
    Flag(
      "json-output",
      "",
      KBool,
      "print the final summary as one compact JSON object instead of log lines",
    ),
    Flag(
      "key-bits",
      "int",
      KInt,
      "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
    ),
    Flag("mac", "string", KString, "MAC primitive name"),
    Flag(
      "memlimit",
      "string",
      KString,
      "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)",
    ),
    Flag(
      "memprofile",
      "string",
      KString,
      "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none",
    ),
    Flag(
      "nonce-bits",
      "int",
      KInt,
      "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
    ),
    Flag("parallax", "string", KString, "parallax layer: on | off"),
    Flag(
      "payload-mode",
      "string",
      KString,
      "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii",
    ),
    Flag(
      "payload-size",
      "string",
      KString,
      "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
    ),
    Flag(
      "profile",
      "string",
      KString,
      "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair",
    ),
    Flag(
      "rekey-every",
      "int",
      KInt64,
      "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never",
    ),
    Flag(
      "seed",
      "uint",
      KUint64,
      "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts",
    ),
    Flag(
      "shape",
      "string",
      KString,
      "cipher surface to exercise: stream | message | stream_one_shot | both",
    ),
    Flag("wrapper", "string", KString, "wrapper layer: on | off"),
  ]
}

fn defaults() -> Dict(String, Value) {
  dict.from_list([
    #("barrier-fill", VInt(0)),
    #("blob-cycle-every", VInt(0)),
    #("blob-mode", VInt(1)),
    #("chunk-size", VString("0")),
    #("drbg", VString("")),
    #("duration", VString("5m")),
    #("gogc", VInt(0)),
    #("gomaxprocs", VInt(0)),
    #("goroutines", VInt(3)),
    #("hash", VString("areion512")),
    #("iterations", VInt(0)),
    #("json-output", VBool(False)),
    #("key-bits", VInt(0)),
    #("mac", VString("hmac-blake3")),
    #("memlimit", VString("auto")),
    #("memprofile", VString("")),
    #("nonce-bits", VInt(0)),
    #("parallax", VString("on")),
    #("payload-mode", VString("fixed")),
    #("payload-size", VString("16MB")),
    #("profile", VString("")),
    #("rekey-every", VInt(0)),
    #("seed", VInt(0)),
    #("shape", VString("stream")),
    #("wrapper", VString("on")),
  ])
}

fn get_int(values: Dict(String, Value), name: String) -> Int {
  case dict.get(values, name) {
    Ok(VInt(v)) -> v
    _ -> 0
  }
}

fn get_string(values: Dict(String, Value), name: String) -> String {
  case dict.get(values, name) {
    Ok(VString(v)) -> v
    _ -> ""
  }
}

fn get_bool(values: Dict(String, Value), name: String) -> Bool {
  case dict.get(values, name) {
    Ok(VBool(v)) -> v
    _ -> False
  }
}

fn usage() -> Nil {
  let d = defaults()
  loop_ffi.write_stderr(
    "Usage of loop:\n"
    <> string.concat(
      list.map(flag_table(), fn(f) {
        flag_usage(f, case dict.get(d, f.name) {
          Ok(v) -> v
          Error(Nil) -> VString("")
        })
      }),
    ),
  )
}

fn flag_usage(f: Flag, default: Value) -> String {
  let head = case f.label {
    "" -> "  -" <> f.name <> "\n"
    label -> "  -" <> f.name <> " " <> label <> "\n"
  }
  // Gleam-specific. The default-value suffix is composed by hand; a
  // flag library that appends its own renders it itself.
  let suffix = case f.kind, default {
    KInt, VInt(0) -> ""
    KInt, VInt(v) -> " (default " <> int.to_string(v) <> ")"
    KString, VString("") -> ""
    KString, VString(v) -> " (default \"" <> v <> "\")"
    _, _ -> ""
  }
  head <> "    \t" <> f.help <> suffix <> "\n"
}

/// The outcome of parsing the command line.
type Parsed {
  ParsedOk(values: Dict(String, Value))
  ParsedHelp
  ParsedError
}

// Parses argv into the raw flag values. Accepts -name value,
// --name value, -name=value and --name=value; a boolean flag takes no
// value unless given as -name=true / -name=false.
fn parse_argv(args: List(String), values: Dict(String, Value)) -> Parsed {
  case args {
    [] -> ParsedOk(values)
    [arg, ..rest] ->
      case string.starts_with(arg, "-") && string.length(arg) > 1 {
        False -> {
          loop_types.err("unexpected positional arguments: [" <> arg <> "]")
          ParsedError
        }
        True -> parse_flag(arg, rest, values)
      }
  }
}

fn parse_flag(
  arg: String,
  rest: List(String),
  values: Dict(String, Value),
) -> Parsed {
  let name0 = case string.starts_with(arg, "--") {
    True -> string.drop_start(arg, 2)
    False -> string.drop_start(arg, 1)
  }
  case name0 {
    "h" -> ParsedHelp
    "help" -> ParsedHelp
    _ -> {
      let #(name, inline) = case string.split_once(name0, "=") {
        Ok(#(n, v)) -> #(n, Some(v))
        Error(Nil) -> #(name0, None)
      }
      case list.find(flag_table(), fn(f) { f.name == name }) {
        Error(Nil) -> {
          loop_types.err("flag provided but not defined: -" <> name)
          usage()
          ParsedError
        }
        Ok(f) -> take_value(f, inline, rest, values)
      }
    }
  }
}

fn take_value(
  f: Flag,
  inline: Option(String),
  rest: List(String),
  values: Dict(String, Value),
) -> Parsed {
  case value_of(f, inline, rest) {
    Error(Nil) -> {
      loop_types.err("flag needs an argument: -" <> f.name)
      ParsedError
    }
    Ok(#(text, rest1)) ->
      case assign(f.kind, text) {
        Error(Nil) -> {
          loop_types.err(
            "invalid value \"" <> text <> "\" for flag -" <> f.name,
          )
          ParsedError
        }
        Ok(value) -> parse_argv(rest1, dict.insert(values, f.name, value))
      }
  }
}

fn value_of(
  f: Flag,
  inline: Option(String),
  rest: List(String),
) -> Result(#(String, List(String)), Nil) {
  case inline, f.kind, rest {
    Some(v), _, _ -> Ok(#(v, rest))
    None, KBool, _ -> Ok(#("true", rest))
    None, _, [v, ..tail] -> Ok(#(v, tail))
    None, _, [] -> Error(Nil)
  }
}

fn assign(kind: Kind, text: String) -> Result(Value, Nil) {
  case kind {
    KString -> Ok(VString(text))
    KBool ->
      case text {
        "true" -> Ok(VBool(True))
        "false" -> Ok(VBool(False))
        _ -> Error(Nil)
      }
    KUint64 ->
      case string.starts_with(text, "-") {
        True -> Error(Nil)
        False -> int_value(text)
      }
    KInt64 -> int_value(text)
    KInt ->
      case int_value(text) {
        Ok(VInt(v)) if v <= 2_147_483_647 && v >= -2_147_483_647 -> Ok(VInt(v))
        _ -> Error(Nil)
      }
  }
}

fn int_value(text: String) -> Result(Value, Nil) {
  case int.parse(text) {
    Ok(v) -> Ok(VInt(v))
    Error(Nil) -> Error(Nil)
  }
}

// ------------------------------------------------------------------
// Validation
// ------------------------------------------------------------------

// Builds the resolved config from the parsed values. Returns the
// config, or Error(Nil) after printing "loop: <message>" for the
// first failing rule.
fn resolve(v: Dict(String, Value)) -> Result(Config, Nil) {
  case loop_size.parse_duration(get_string(v, "duration")) {
    Ok(ns) if ns > 0 -> resolve_iterations(v, blank_config(ns))
    _ -> {
      loop_types.err(
        "--duration must be positive, got " <> get_string(v, "duration"),
      )
      Error(Nil)
    }
  }
}

fn blank_config(duration_ns: Int) -> Config {
  Config(
    duration_ns: duration_ns,
    iterations: 0,
    workers_requested: 0,
    workers: 0,
    shape: Stream,
    hash: "",
    mac: "",
    payload: 0,
    memlimit: 0,
    memlimit_auto: False,
    gogc: 0,
    parallax: True,
    wrapper: True,
    profile: "",
    key_bits: 0,
    nonce_bits: 0,
    blob_mode: 1,
    chunk_size: 0,
    barrier_fill: 0,
    drbg: "",
    gomaxprocs: 0,
    rekey_every: 0,
    blob_cycle_every: 0,
    payload_mode: loop_types.Fixed,
    seed: 0,
    json_output: False,
    memprofile: "",
  )
}

fn resolve_iterations(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let n = get_int(v, "iterations")
  case n < 0 {
    True -> {
      loop_types.err("--iterations must be >= 0, got " <> int.to_string(n))
      Error(Nil)
    }
    False -> resolve_workers(v, Config(..cfg, iterations: n))
  }
}

fn resolve_workers(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let g = get_int(v, "goroutines")
  case g < 1 || g > loop_types.max_workers {
    True -> {
      loop_types.err(
        "--goroutines must be in 1.."
        <> int.to_string(loop_types.max_workers)
        <> ", got "
        <> int.to_string(g),
      )
      Error(Nil)
    }
    False ->
      resolve_shape(v, Config(..cfg, workers_requested: g, workers: g))
  }
}

fn resolve_shape(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let shape = get_string(v, "shape")
  case loop_types.parse_shape(shape) {
    Error(Nil) -> {
      loop_types.err(
        "--shape must be stream | message | stream_one_shot | both, got \""
        <> shape
        <> "\"",
      )
      Error(Nil)
    }
    Ok(s) -> resolve_hash(v, Config(..cfg, shape: s))
  }
}

fn resolve_hash(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let hash = get_string(v, "hash")
  case list.contains(itb3_gleam.hash_names(), hash) {
    False -> {
      loop_types.err(
        "--hash \"" <> hash <> "\" is not a registered hash primitive",
      )
      Error(Nil)
    }
    // The MAC name is validated by Init: no registry enumeration for
    // MAC primitives crosses the boundary.
    True ->
      resolve_payload(v, Config(..cfg, hash: hash, mac: get_string(v, "mac")))
  }
}

fn resolve_payload(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let size = get_string(v, "payload-size")
  case loop_size.parse_size(size) {
    Error(Nil) -> {
      loop_types.err("--payload-size: invalid size \"" <> size <> "\"")
      Error(Nil)
    }
    Ok(n) ->
      case n < 1 {
        True -> {
          loop_types.err("--payload-size must be at least 1 byte")
          Error(Nil)
        }
        False -> resolve_memlimit(v, Config(..cfg, payload: n))
      }
  }
}

fn resolve_memlimit(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  case get_string(v, "memlimit") {
    "auto" -> {
      let limit = case cfg.workers <= 3 {
        True -> 1_073_741_824
        False -> 268_435_456
      }
      resolve_gogc(v, Config(..cfg, memlimit_auto: True, memlimit: limit))
    }
    size ->
      case loop_size.parse_size(size) {
        Error(Nil) -> {
          loop_types.err("--memlimit: invalid size \"" <> size <> "\"")
          Error(Nil)
        }
        Ok(n) -> resolve_gogc(v, Config(..cfg, memlimit: n))
      }
  }
}

fn resolve_gogc(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let g = get_int(v, "gogc")
  case g < 0 {
    True -> {
      loop_types.err("--gogc must be >= 0, got " <> int.to_string(g))
      Error(Nil)
    }
    False -> resolve_layers(v, Config(..cfg, gogc: g))
  }
}

fn resolve_layers(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  case on_off_value(get_string(v, "parallax")) {
    Error(Nil) -> {
      loop_types.err(
        "--parallax must be on | off, got \"" <> get_string(v, "parallax") <> "\"",
      )
      Error(Nil)
    }
    Ok(p) ->
      case on_off_value(get_string(v, "wrapper")) {
        Error(Nil) -> {
          loop_types.err(
            "--wrapper must be on | off, got \""
            <> get_string(v, "wrapper")
            <> "\"",
          )
          Error(Nil)
        }
        Ok(w) -> resolve_profile(v, Config(..cfg, parallax: p, wrapper: w))
      }
  }
}

fn on_off_value(text: String) -> Result(Bool, Nil) {
  case text {
    "on" -> Ok(True)
    "off" -> Ok(False)
    _ -> Error(Nil)
  }
}

fn resolve_profile(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  case get_string(v, "profile") {
    "" -> resolve_key_bits(v, cfg)
    name ->
      case profile_surface(name) {
        Error(Nil) -> Error(Nil)
        Ok(surface) ->
          resolve_key_bits(
            v,
            Config(
              ..cfg,
              profile: name,
              shape: narrow_shape(cfg.shape, surface),
            ),
          )
      }
  }
}

// Resolves a registered profile to the shape family its record's mode
// exposes by reading the record through the binding's lookup: a mode
// beginning with "streaming" exposes the stream surfaces, one
// beginning with "singlemsg" the message surface, "blob-only" none.
fn profile_surface(name: String) -> Result(Shape, Nil) {
  case itb3_gleam.lookup(name) {
    Error(_) -> {
      loop_types.err(
        "--profile \"" <> name <> "\" is not a registered triple profile",
      )
      Error(Nil)
    }
    Ok(json) -> {
      let mode = record_str(json, "mode")
      case
        string.starts_with(mode, "streaming"),
        string.starts_with(mode, "singlemsg")
      {
        True, _ -> Ok(Stream)
        _, True -> Ok(Message)
        _, _ -> {
          loop_types.err(
            "--profile \""
            <> name
            <> "\" carries no cipher surface (blob-only mode)",
          )
          Error(Nil)
        }
      }
    }
  }
}

// Applies a --profile's surface to the requested shape: a
// message-surface profile forces message; a stream-surface profile
// keeps stream or stream_one_shot as requested and turns message or
// both into stream.
fn narrow_shape(requested: Shape, surface: Shape) -> Shape {
  case surface, requested {
    Message, _ -> Message
    _, StreamOneShot -> StreamOneShot
    _, _ -> Stream
  }
}

fn resolve_key_bits(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let k = get_int(v, "key-bits")
  case k == 0 || k == 512 || k == 1024 || k == 2048 {
    True -> resolve_nonce_bits(v, Config(..cfg, key_bits: k))
    False -> {
      loop_types.err(
        "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got "
        <> int.to_string(k),
      )
      Error(Nil)
    }
  }
}

fn resolve_nonce_bits(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let n = get_int(v, "nonce-bits")
  case n == 0 || n == 128 || n == 256 || n == 512 {
    True -> resolve_blob_mode(v, Config(..cfg, nonce_bits: n))
    False -> {
      loop_types.err(
        "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got "
        <> int.to_string(n),
      )
      Error(Nil)
    }
  }
}

fn resolve_blob_mode(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let m = get_int(v, "blob-mode")
  case m == 1 || m == 2 {
    True -> resolve_barrier_fill(v, Config(..cfg, blob_mode: m))
    False -> {
      loop_types.err(
        "--blob-mode must be 1 (per-region) | 2 (per-container), got "
        <> int.to_string(m),
      )
      Error(Nil)
    }
  }
}

fn resolve_barrier_fill(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let b = get_int(v, "barrier-fill")
  case b == 0 || b == 1 || b == 2 || b == 4 || b == 8 || b == 16 || b == 32 {
    // The DRBG name is validated by Init: the C ABI enumerates no DRBG
    // names.
    True ->
      resolve_chunk_size(
        v,
        Config(..cfg, barrier_fill: b, drbg: get_string(v, "drbg")),
      )
    False -> {
      loop_types.err(
        "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got "
        <> int.to_string(b),
      )
      Error(Nil)
    }
  }
}

fn resolve_chunk_size(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let size = get_string(v, "chunk-size")
  case loop_size.parse_size(size) {
    Error(Nil) -> {
      loop_types.err("--chunk-size: invalid size \"" <> size <> "\"")
      Error(Nil)
    }
    Ok(n) -> resolve_gomaxprocs(v, Config(..cfg, chunk_size: n))
  }
}

fn resolve_gomaxprocs(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let g = get_int(v, "gomaxprocs")
  case g < 0 {
    True -> {
      loop_types.err(
        "--gomaxprocs must be > 0 when specified, got " <> int.to_string(g),
      )
      Error(Nil)
    }
    False -> resolve_rekey(v, Config(..cfg, gomaxprocs: g))
  }
}

fn resolve_rekey(v: Dict(String, Value), cfg: Config) -> Result(Config, Nil) {
  let r = get_int(v, "rekey-every")
  case r < 0 {
    True -> {
      loop_types.err("--rekey-every must be >= 0, got " <> int.to_string(r))
      Error(Nil)
    }
    False -> resolve_blob_cycle(v, Config(..cfg, rekey_every: r))
  }
}

fn resolve_blob_cycle(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let b = get_int(v, "blob-cycle-every")
  case b < 0 {
    True -> {
      loop_types.err(
        "--blob-cycle-every must be >= 0, got " <> int.to_string(b),
      )
      Error(Nil)
    }
    False -> resolve_payload_mode(v, Config(..cfg, blob_cycle_every: b))
  }
}

fn resolve_payload_mode(
  v: Dict(String, Value),
  cfg: Config,
) -> Result(Config, Nil) {
  let mode = get_string(v, "payload-mode")
  case loop_payload.parse_mode(mode) {
    Error(Nil) -> {
      loop_types.err(
        "--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \""
        <> mode
        <> "\"",
      )
      Error(Nil)
    }
    Ok(m) ->
      Ok(
        Config(
          ..cfg,
          payload_mode: m,
          seed: get_int(v, "seed"),
          json_output: get_bool(v, "json-output"),
          memprofile: get_string(v, "memprofile"),
        ),
      )
  }
}

// ------------------------------------------------------------------
// Profile records
// ------------------------------------------------------------------

// Gleam-specific. The binding returns a profile record as JSON text,
// and this binding pins no JSON decoder; the two probes below read a
// value by its key from that text. Profile record strings are
// restricted to [a-z0-9-] and the numbers are plain decimals, so a
// quoted or unquoted run after the key is one complete value — the
// same reading the C reference does.
fn record_str(json: String, key: String) -> String {
  case string.split_once(json, "\"" <> key <> "\":\"") {
    Error(Nil) -> "-"
    Ok(#(_, rest)) ->
      case string.split_once(rest, "\"") {
        Ok(#("", _)) -> "-"
        Ok(#(value, _)) -> value
        Error(Nil) -> "-"
      }
  }
}

fn record_int(json: String, key: String) -> Int {
  case string.split_once(json, "\"" <> key <> "\":") {
    Error(Nil) -> 0
    Ok(#(_, rest)) -> leading_int(rest, "")
  }
}

fn leading_int(text: String, acc: String) -> Int {
  case string.pop_grapheme(text) {
    Error(Nil) -> parse_or_zero(acc)
    Ok(#(c, rest)) ->
      case int.parse(c) {
        Ok(_) -> leading_int(rest, acc <> c)
        Error(Nil) -> parse_or_zero(acc)
      }
  }
}

fn parse_or_zero(text: String) -> Int {
  case int.parse(text) {
    Ok(v) -> v
    Error(Nil) -> 0
  }
}

fn record_bool(json: String, key: String) -> Bool {
  string.contains(json, "\"" <> key <> "\":true")
}

fn record_has(json: String, key: String) -> Bool {
  string.contains(json, "\"" <> key <> "\":")
}

// ------------------------------------------------------------------
// Pipelines
// ------------------------------------------------------------------

// Folds a keystream primitive into opts for any layer the named
// profile leaves unfilled but the operator asked for.
//
// A profile built around a primitive that is safe only inside the
// Interlocked Barrier ships with no parallax palette and no outer
// cipher: both layers run outside the barrier, where that primitive
// would stand bare, so the recipe leaves them unnamed rather than
// naming a primitive that must not key them. Engaging either layer
// therefore needs a keystream-capable primitive supplied from outside
// the recipe; without it construction fails on a palette below its
// minimum or an unnamed outer cipher, and the primitive that most
// deserves stressing becomes the one that cannot be stressed with
// those layers engaged.
//
// AES-CMAC is PRF-grade, so it is sound outside the Interlocked
// Barrier, and it is the closest relative of the AES-based inner
// primitive whose profiles need this fill. Overrides fold into the
// resolved record the blob carries, so the receiver rebuilds the same
// shape from the blob alone.
fn fill_keystream_layers(
  name: String,
  want_parallax: Bool,
  want_wrapper: Bool,
) -> Result(List(#(String, String)), Nil) {
  case itb3_gleam.lookup(name) {
    Error(_) -> {
      loop_types.err(
        "--profile \"" <> name <> "\" is not a registered triple profile",
      )
      Error(Nil)
    }
    Ok(json) -> {
      let fill = loop_types.keystream_fill_cipher
      let palette = case want_parallax && !record_has(json, "palette") {
        False -> []
        True -> {
          let triple = [
            #("parallaxPalette", fill <> "," <> fill <> "," <> fill),
          ]
          // A recipe that never carried a palette never carried a
          // segment size either, and the schedule rejects zero.
          case record_has(json, "segment") {
            True -> triple
            False ->
              list.append(triple, [#("parallaxSegmentSize", "4093")])
          }
        }
      }
      let outer = case want_wrapper && !record_has(json, "outer") {
        True -> [#("outerCipher", fill)]
        False -> []
      }
      Ok(list.append(palette, outer))
    }
  }
}

// Constructs one Pipeline against `profile` with every flag-carried
// override in the opts list (zero values included — the shared
// library treats zero as "profile default"), then obtains the Init
// blob once through save: the binding's init entry does not hand the
// blob back, and the bytes are the ones Init produced. Later blob
// reopens use the retained blob; save is never called again.
fn build_pipeline(
  cfg: Config,
  profile: String,
) -> Result(#(Pipeline, BitArray), Nil) {
  let base = [
    #("innerHash", cfg.hash),
    #("macName", cfg.mac),
    #("withParallax", loop_types.bool_text(cfg.parallax)),
    #("withWrapper", loop_types.bool_text(cfg.wrapper)),
    #("keyBits", int.to_string(cfg.key_bits)),
    #("nonceBits", int.to_string(cfg.nonce_bits)),
    #("barrierFill", int.to_string(cfg.barrier_fill)),
    #("drbg", cfg.drbg),
    #("chunkSize", int.to_string(cfg.chunk_size)),
  ]
  let extra = case cfg.profile {
    "" -> Ok([])
    name -> fill_keystream_layers(name, cfg.parallax, cfg.wrapper)
  }
  case extra {
    Error(Nil) -> Error(Nil)
    Ok(fill) -> {
      case fill {
        [] -> Nil
        _ ->
          loop_types.err(
            cfg.profile
            <> " leaves the requested keystream layers unnamed; "
            <> loop_types.keystream_fill_cipher
            <> " supplied for them",
          )
      }
      case pipeline.new(profile, list.append(base, fill)) {
        Error(ItbError(status, detail)) -> {
          loop_types.err(
            "Init(" <> profile <> "): " <> loop_types.status_text(status, detail),
          )
          Error(Nil)
        }
        Ok(pipe) ->
          case pipeline.save(pipe) {
            Error(ItbError(status, detail)) -> {
              loop_types.err(
                "Save("
                <> profile
                <> "): "
                <> loop_types.status_text(status, detail),
              )
              pipeline.free(pipe)
              Error(Nil)
            }
            Ok(blob) -> apply_blob_mode(cfg.blob_mode, profile, pipe, blob)
          }
      }
    }
  }
}

// The sizing mode is not an opts knob: under --blob-mode 2 the Init
// blob is edited and the pipeline reopened from it, so the retained
// blob (the one blob-cycle reopens from) carries the edited mode.
fn apply_blob_mode(
  mode: Int,
  profile: String,
  pipe: Pipeline,
  blob: BitArray,
) -> Result(#(Pipeline, BitArray), Nil) {
  case mode {
    1 -> {
      log_pipeline_initialised(profile, blob)
      Ok(#(pipe, blob))
    }
    _ -> {
      pipeline.free(pipe)
      case edit_inner_blob_mode(blob, mode) {
        Error(Nil) -> {
          loop_types.err("rewrite blob mode: inner blob mode field not found")
          Error(Nil)
        }
        Ok(edited) ->
          case pipeline.load(edited) {
            Error(ItbError(status, detail)) -> {
              loop_types.err(
                "reload Mode 2 blob: " <> loop_types.status_text(status, detail),
              )
              Error(Nil)
            }
            Ok(reloaded) -> {
              log_pipeline_initialised(profile, edited)
              Ok(#(reloaded, edited))
            }
          }
      }
    }
  }
}

// Gleam-specific. This binding pins no JSON encoder, so the inner
// blob's integer "mode" (1 = per-region, 2 = per-container) is set by
// a targeted edit, the same one the C reference makes: the search
// starts at the inner blob ("ib"), because the profile record "p"
// carries its own string "mode", and nothing before "ib" is touched.
// Both shipped modes are one digit wide, so the blob length does not
// change.
fn edit_inner_blob_mode(blob: BitArray, mode: Int) -> Result(BitArray, Nil) {
  let ib_key = "\"ib\":{"
  let mode_key = "\"mode\":"
  case bit_array.to_string(blob) {
    Error(Nil) -> Error(Nil)
    Ok(text) ->
      case string.split_once(text, ib_key) {
        Error(Nil) -> Error(Nil)
        Ok(#(before, inner)) ->
          case string.split_once(inner, mode_key) {
            Error(Nil) -> Error(Nil)
            Ok(#(mid, rest)) ->
              case string.pop_grapheme(rest) {
                Ok(#(digit, tail)) if digit == "1" || digit == "2" ->
                  case string.pop_grapheme(tail) {
                    Ok(#(next, _)) ->
                      case int.parse(next) {
                        Ok(_) -> Error(Nil)
                        Error(Nil) ->
                          Ok(bit_array.from_string(
                            before
                            <> ib_key
                            <> mid
                            <> mode_key
                            <> int.to_string(mode)
                            <> tail,
                          ))
                      }
                    Error(Nil) -> Error(Nil)
                  }
                _ -> Error(Nil)
              }
          }
      }
  }
}

// Prints the construction line with the recipe read back from the
// blob the Pipeline handed out, not echoed from the flags: every
// construction override is proven to have reached the library by the
// value the receiver would see. Record values that are empty (a No
// MAC profile's MAC, a mixed profile's single hash) print as "-".
fn log_pipeline_initialised(profile: String, blob: BitArray) -> Nil {
  let size = int.to_string(bit_array.byte_size(blob))
  case itb3_gleam.inspect(blob) {
    Error(ItbError(_, detail)) ->
      loop_types.log(
        "pipeline initialised: profile="
        <> profile
        <> " blob="
        <> size
        <> " bytes (inspect: "
        <> detail
        <> ")",
      )
    Ok(json) ->
      loop_types.log(
        "pipeline initialised: profile="
        <> profile
        <> " blob="
        <> size
        <> " bytes hash="
        <> record_str(json, "hash")
        <> " key-bits="
        <> int.to_string(record_int(json, "keybits"))
        <> " nonce-bits="
        <> int.to_string(record_int(json, "nonce_bits"))
        <> " barrier-fill="
        <> int.to_string(record_int(json, "barrier_fill"))
        <> " chunk-size="
        <> int.to_string(record_int(json, "chunk"))
        <> " mac="
        <> record_str(json, "mac")
        <> " parallax="
        <> loop_types.on_off(record_bool(json, "parallax"))
        <> " wrapper="
        <> loop_types.on_off(record_bool(json, "wrapper"))
        <> case record_int(json, "container_mode") {
          2 -> " container-mode=2"
          _ -> ""
        }
        <> case record_str(json, "drbg") {
          "-" -> ""
          drbg -> " drbg=" <> drbg
        },
      )
  }
}

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------

/// Entry point: the emulator calls this with the command line after
/// `-extra`. The closed-pipe filter goes in before the first write, so
/// a consumer that stops reading ends the run silently with 141.
pub fn main() -> Nil {
  loop_ffi.install_closed_pipe_filter()
  loop_ffi.halt(run(loop_ffi.argv()))
}

fn run(args: List(String)) -> Int {
  case parse_argv(args, defaults()) {
    ParsedHelp -> {
      usage()
      0
    }
    ParsedError -> 2
    ParsedOk(values) ->
      case resolve(values) {
        Error(Nil) -> 2
        Ok(cfg) -> shape_runtime(cfg)
      }
  }
}

/// Runtime shaping. A long run under allocation churn grows the Go
/// heap inside the shared library without bound unless a soft limit
/// paces the collector, so a limit is always in force: an explicit
/// --memlimit is set as given, and auto caps the heap only when the
/// runtime reports no limit at all (a limit already installed from
/// the environment is left standing). The GC percentage and
/// GOMAXPROCS are set only when their flag is non-zero — a zero flag
/// skips the setter rather than calling it with zero, because zero is
/// a real value to the GC-percent setter, and a call would clobber
/// whatever the environment installed. All of it lands before any
/// Pipeline exists so the baselines are taken under the shaped
/// runtime.
fn shape_runtime(cfg0: Config) -> Int {
  case cfg0.memlimit_auto {
    True ->
      case itb3_gleam.set_memory_limit(-1) == 9_223_372_036_854_775_807 {
        True -> {
          let _ = itb3_gleam.set_memory_limit(cfg0.memlimit)
          Nil
        }
        False -> Nil
      }
    False -> {
      let _ = itb3_gleam.set_memory_limit(cfg0.memlimit)
      Nil
    }
  }
  let cfg = Config(..cfg0, memlimit: itb3_gleam.set_memory_limit(-1))
  case cfg.gogc > 0 {
    True -> {
      let _ = itb3_gleam.set_gc_percent(cfg.gogc)
      Nil
    }
    False -> Nil
  }
  case cfg.gomaxprocs > 0 {
    True -> {
      let _ = itb3_gleam.set_gomaxprocs(cfg.gomaxprocs)
      Nil
    }
    False -> Nil
  }
  start_lines(cfg)
  build(cfg)
}

fn start_lines(cfg: Config) -> Nil {
  let i = int.to_string
  loop_types.log(
    "start: duration="
    <> loop_size.human_duration(cfg.duration_ns)
    <> " iterations="
    <> i(cfg.iterations)
    <> " goroutines="
    <> i(cfg.workers_requested)
    <> " workers="
    <> i(cfg.workers)
    <> " concurrency="
    <> loop_types.concurrency
    <> " shape="
    <> loop_types.shape_name(cfg.shape)
    <> " hash="
    <> cfg.hash
    <> " mac="
    <> cfg.mac
    <> " payload="
    <> loop_size.human_bytes(cfg.payload)
    <> " memlimit="
    <> loop_size.human_bytes(cfg.memlimit)
    <> " parallax="
    <> loop_types.on_off(cfg.parallax)
    <> " wrapper="
    <> loop_types.on_off(cfg.wrapper),
  )
  loop_types.log(
    "overrides: profile=\""
    <> cfg.profile
    <> "\" key-bits="
    <> i(cfg.key_bits)
    <> " nonce-bits="
    <> i(cfg.nonce_bits)
    <> " chunk-size="
    <> loop_size.human_bytes(cfg.chunk_size)
    <> " barrier-fill="
    <> i(cfg.barrier_fill)
    <> " gomaxprocs="
    <> i(cfg.gomaxprocs)
    <> " rekey-every="
    <> i(cfg.rekey_every)
    <> " blob-cycle-every="
    <> i(cfg.blob_cycle_every)
    <> " payload-mode="
    <> loop_payload.mode_name(cfg.payload_mode)
    <> " seed="
    <> i(cfg.seed)
    <> " json-output="
    <> loop_types.bool_text(cfg.json_output)
    <> case cfg.blob_mode {
      1 -> ""
      m -> " blob-mode=" <> i(m)
    }
    <> case cfg.drbg {
      "" -> ""
      d -> " drbg=" <> d
    },
  )
  loop_types.log(
    "policy: microbatch-tiers="
    <> loop_types.policy_label("ITB_MICROBATCH_TIERS")
    <> " hashpool-starters="
    <> loop_types.policy_label("ITB_HASHPOOL_STARTERS"),
  )
}

// Pipeline construction — one shared handle per exercised shape.
// stream and stream_one_shot share the streaming handle.
fn build(cfg: Config) -> Int {
  let stream_profile = case cfg.profile {
    "" -> loop_types.default_stream_profile
    name -> name
  }
  let msg_profile = case cfg.profile {
    "" -> loop_types.default_message_profile
    name -> name
  }
  let want_stream = case cfg.shape {
    Stream -> True
    StreamOneShot -> True
    Both -> True
    Message -> False
  }
  let want_msg = case cfg.shape {
    Message -> True
    Both -> True
    _ -> False
  }
  case build_optional(want_stream, cfg, stream_profile) {
    Error(Nil) -> 1
    Ok(#(stream_pipe, stream_blob)) ->
      case build_optional(want_msg, cfg, msg_profile) {
        Error(Nil) -> 1
        Ok(#(msg_pipe, msg_blob)) ->
          launch(
            cfg,
            stream_profile,
            stream_pipe,
            stream_blob,
            msg_profile,
            msg_pipe,
            msg_blob,
          )
      }
  }
}

fn build_optional(
  want: Bool,
  cfg: Config,
  profile: String,
) -> Result(#(Option(Pipeline), BitArray), Nil) {
  case want {
    False -> Ok(#(None, <<>>))
    True ->
      case build_pipeline(cfg, profile) {
        Ok(#(pipe, blob)) -> Ok(#(Some(pipe), blob))
        Error(Nil) -> Error(Nil)
      }
  }
}

fn launch(
  cfg: Config,
  stream_profile: String,
  stream_pipe: Option(Pipeline),
  stream_blob: BitArray,
  msg_profile: String,
  msg_pipe: Option(Pipeline),
  msg_blob: BitArray,
) -> Int {
  let flags = loop_state.new_flags()
  let counts = loop_state.new_counts()
  let state = loop_state.start(stream_pipe, msg_pipe, stream_blob, msg_blob)
  let run =
    Run(
      cfg: cfg,
      state: state,
      flags: flags,
      counts: counts,
      stream_profile: stream_profile,
      msg_profile: msg_profile,
    )
  install_signals(flags)

  // Allocation posture. Per-worker plaintexts are built once and held
  // for the whole run (rotating mode rebuilds them per iteration);
  // the pump accumulator is a per-iteration list the collector
  // reclaims, and the message and one-shot outputs are byte strings
  // the binding returns per call. Under the default fixed CSPRNG mode
  // every worker's buffer is distinct, so cross-worker data crossover
  // is detectable; pattern modes trade that property for content
  // edge-case coverage.
  let ids = worker_ids(cfg.workers)
  let plaintexts =
    list.map(ids, fn(i) {
      let #(buf, _rng) =
        loop_payload.fill(
          cfg.payload_mode,
          cfg.seed != 0,
          loop_payload.seed_worker(cfg.seed, i),
          cfg.payload,
        )
      buf
    })

  // Warmup barrier. Every worker runs one iteration and waits; the
  // clock starts only once all of them have paid their first-call
  // costs (pool warm-up, lazy kernel dispatch, page faults on the
  // payload buffers), and the RSS and pool baselines taken here
  // describe a process that has already run the whole cipher path
  // once per worker.
  let warmup_start = loop_size.now_ns()
  let parent = loop_ffi.self_pid()
  let workers =
    list.map(list.zip(ids, plaintexts), fn(entry) {
      let #(i, plaintext) = entry
      let pid = loop_worker.start(run, i, plaintext, parent)
      loop_ffi.watch_process(pid, parent, WorkerDied)
      loop_state.watch(pid, state)
      #(pid, i)
    })
  await_warmup(workers)
  let #(rss_warmup, rss_peak0) = loop_summary.read_rss()
  let pool_warmup = loop_summary.pool_snapshot()
  let warmup_ns = loop_size.now_ns() - warmup_start
  loop_types.log(
    "warmup: "
    <> int.to_string(cfg.workers)
    <> " workers x 1 iter completed in "
    <> loop_size.human_duration(
      { warmup_ns + 50_000_000 } / 100_000_000 * 100_000_000,
    )
    <> " (baseline rss="
    <> loop_size.human_bytes(rss_warmup)
    <> ")",
  )

  // Open the gate; in duration mode a timer asks the workers to stop
  // once the deadline passes.
  let start_ns = loop_size.now_ns()
  list.each(workers, fn(w) { loop_ffi.send(w.0, loop_worker.Release) })
  let timer = case cfg.iterations {
    0 ->
      Some(loop_ffi.send_after(cfg.duration_ns / 1_000_000, parent, Deadline))
    _ -> None
  }
  let stats = collect(workers, flags, [])
  case timer {
    Some(t) -> loop_ffi.cancel_timer(t)
    None -> Nil
  }
  let finish_ns =
    list.fold(list.map(stats, fn(s) { s.finish_ns }), start_ns, int.max)
  let elapsed_ns = finish_ns - start_ns
  let #(rss_final, rss_peak) = loop_summary.read_rss()
  let pool_steady = loop_summary.pool_snapshot()
  write_memprofile(cfg.memprofile)
  let ordered = list.sort(stats, fn(a, b) { int.compare(a.id, b.id) })
  let rc =
    loop_summary.final(
      run,
      ordered,
      elapsed_ns,
      #(rss_warmup, int.max(rss_peak0, rss_peak), rss_final),
      #(pool_warmup, pool_steady),
    )
  let grant = loop_state.handles(state)
  free_pipe(grant.stream_pipe)
  free_pipe(grant.msg_pipe)
  loop_state.stop_process(state)
  rc
}

fn worker_ids(n: Int) -> List(Int) {
  build_ids(n - 1, [])
}

fn build_ids(i: Int, acc: List(Int)) -> List(Int) {
  case i < 0 {
    True -> acc
    False -> build_ids(i - 1, [i, ..acc])
  }
}

fn free_pipe(pipe: Option(Pipeline)) -> Nil {
  case pipe {
    Some(p) -> pipeline.free(p)
    None -> Nil
  }
}

fn write_memprofile(path: String) -> Nil {
  case path {
    "" -> Nil
    _ ->
      case itb3_gleam.write_heap_profile(path) {
        Ok(Nil) ->
          loop_types.log("memprofile: heap profile written to " <> path)
        Error(ItbError(_, detail)) -> loop_types.err("memprofile: " <> detail)
      }
  }
}

/// Graceful stop. A termination signal sets the run's stop request,
/// which every worker checks before starting an iteration, so the
/// signal interrupts nothing mid-call — the in-flight encrypt /
/// decrypt / compare completes, the worker returns, and the partial
/// summary prints with the verdict the completed iterations earned.
///
/// Gleam-specific. SIGINT never reaches BEAM code: the emulator's
/// break handler owns it below the signal server, and the signal
/// server does not accept it at all. The launcher closes that gap by
/// trapping the interrupt itself and sending the emulator a
/// termination signal, which the handler installed here receives.
fn install_signals(flags: Flags) -> Nil {
  loop_ffi.install_signal_handler(flags)
}

// Every worker reports its warmup iteration before the clock starts.
// A worker that died instead of reporting is not waited for: the
// watcher turns its exit into the same arrival, and the run goes on
// to the summary that will carry the failure.
fn await_warmup(workers: List(#(Pid, Int))) -> Nil {
  case workers {
    [] -> Nil
    _ ->
      case loop_ffi.receive_any() {
        WarmupDone(pid) -> await_warmup(drop_worker(workers, pid))
        WorkerDied(pid, reason) -> {
          loop_ffi.send(loop_ffi.self_pid(), WorkerDied(pid, reason))
          await_warmup(drop_worker(workers, pid))
        }
        _ -> await_warmup(workers)
      }
  }
}

// Waits for every worker, turning the duration deadline into the stop
// request the workers poll. A worker that dies without reporting is
// recorded as a worker error so the run cannot hang on it.
fn collect(
  workers: List(#(Pid, Int)),
  flags: Flags,
  acc: List(WStats),
) -> List(WStats) {
  case workers {
    [] -> acc
    _ ->
      case loop_ffi.receive_any() {
        Deadline -> {
          loop_state.request_stop(flags)
          collect(workers, flags, acc)
        }
        WorkerDone(pid, stats) ->
          collect(drop_worker(workers, pid), flags, [stats, ..acc])
        WorkerDied(pid, reason) ->
          case list.find(workers, fn(w) { w.0 == pid }) {
            Error(Nil) -> collect(workers, flags, acc)
            Ok(#(_, id)) -> {
              loop_state.request_stop(flags)
              collect(drop_worker(workers, pid), flags, [
                died(id, reason),
                ..acc
              ])
            }
          }
        _ -> collect(workers, flags, acc)
      }
  }
}

fn drop_worker(workers: List(#(Pid, Int)), pid: Pid) -> List(#(Pid, Int)) {
  list.filter(workers, fn(w) { w.0 != pid })
}

fn died(id: Int, reason: String) -> WStats {
  WStats(
    id: id,
    iters: 0,
    bytes_enc: 0,
    bytes_dec: 0,
    nanos_enc: 0,
    nanos_dec: 0,
    finish_ns: loop_size.now_ns(),
    failed: True,
    error: "g" <> int.to_string(id) <> " exited: " <> reason,
  )
}
