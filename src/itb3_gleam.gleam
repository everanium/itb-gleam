//// Public entry point of the ITB Gleam binding.
////
//// Thin proxy over the ITB Erlang binding's Triple Pipeline surface
//// (bindings/erlang, module `itb3`) via native BEAM bytecode interop
//// — the Gleam layer calls the Erlang module directly through the
//// shape-normalising FFI adapter (src/itb3_gleam_ffi.erl) and adds no
//// FFI hop of its own. The only native code in the stack is the
//// Erlang binding's NIF shim. No ITB construction logic lives in
//// this binding: profile names, opts keys, and every primitive name
//// are opaque strings passed through to Go for validation.
////
//// The top-level module is named `itb3_gleam` rather than `itb3`
//// because the BEAM module name `itb3` belongs to the Erlang backend
//// this binding proxies; the pipeline / stream surface lives under
//// `itb3/pipeline` and `itb3/stream`.
////
//// Quick start:
////
////     import itb3/pipeline
////
////     let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
////     let assert Ok(blob) = pipeline.save(sender)
////     let assert Ok(receiver) = pipeline.load(blob)
////     let assert Ok(wire) = pipeline.encrypt_message(sender, <<"hi":utf8>>)
////     let assert Ok(back) = pipeline.decrypt_message(receiver, wire)
////     pipeline.free(receiver)
////     pipeline.free(sender)
////
//// Errors follow the `Result(a, ItbError)` idiom; `status` is the
//// C binding's status table entry rendered as a string (e.g.
//// "mac_failure", "bad_input", "profile_exists") and `detail` is
//// the Go-side diagnostic fetched immediately after the failing
//// call (the underlying store is process-global last-write-wins, so
//// under concurrent use the text may belong to a different call;
//// the status is always attributable).

/// Failure surfaced by a libitb3 call: the C binding's status table
/// entry as a string plus the Go-side diagnostic text.
pub type ItbError {
  ItbError(status: String, detail: String)
}

/// Opts accumulate into the URL-query string consumed by libitb3;
/// the binding performs no validation — Go rejects unknown keys and
/// bad values with a diagnostic in the error detail.
pub type Opts =
  List(#(String, String))

/// The libitb3 library version string (e.g. "0.5.1").
@external(erlang, "itb3_gleam_ffi", "version")
pub fn version() -> Result(String, ItbError)

/// The fill cipher the auto DRBG tier selected on this host
/// ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
/// `drbg` option is empty, resolved per host and recorded in no blob.
@external(erlang, "itb3_gleam_ffi", "drbg_auto_tier")
pub fn drbg_auto_tier() -> Result(String, ItbError)

/// Decodes the blob's embedded profile record without opening a
/// Pipeline and returns it as the JSON text libitb3 emits; absent keys
/// are optional fields at their zero value. No registry read, no
/// primitive probe.
@external(erlang, "itb3_gleam_ffi", "inspect")
pub fn inspect(blob: BitArray) -> Result(String, ItbError)

/// Registers a profile record under `name` so subsequent
/// `pipeline.new` / `lookup` calls resolve it. `profile_json` is the
/// record as JSON text — the shape `inspect` / `lookup` return; a
/// `name` key inside it, if present, must be empty or equal to
/// `name`. Validation is performed by libitb3; a duplicate name fails
/// with status "profile_exists".
@external(erlang, "itb3_gleam_ffi", "register")
pub fn register(name: String, profile_json: String) -> Result(Nil, ItbError)

/// The profile record registered under `name` (a shipped catalogue
/// entry or a prior `register`) as JSON text. An unknown name fails
/// with status "unknown_profile".
@external(erlang, "itb3_gleam_ffi", "lookup")
pub fn lookup(name: String) -> Result(String, ItbError)

/// The sorted list of every registered profile name.
@external(erlang, "itb3_gleam_ffi", "profiles")
pub fn profiles() -> List(String)

/// The shipped hash-primitive registry in canonical order. These are
/// the names `pipeline.new` accepts under the `innerHash` opts key,
/// so a caller validating a primitive name reads it from here rather
/// than carrying a list of its own.
@external(erlang, "itb3_gleam_ffi", "hash_names")
pub fn hash_names() -> List(String)

/// The Go-side diagnostic recorded by the most recent failing libitb3
/// call (process-global last-write-wins; "" when none). The error
/// values already carry this detail — direct use is for ad-hoc
/// debugging only.
@external(erlang, "itb3_gleam_ffi", "last_error")
pub fn last_error() -> String

/// The numeric libitb3 status code behind an `ItbError`'s status,
/// mirroring the C ABI enum. The error values carry the status name,
/// which is what Gleam code matches on; the number is what a
/// diagnostic quotes when it has to name the code the library itself
/// uses. A name outside the table is the internal-error code.
@external(erlang, "itb3_gleam_ffi", "status_code")
pub fn status_code(status: String) -> Int

/// Sets the Go runtime's soft heap limit in bytes; returns the
/// previous limit. A negative value queries without changing.
@external(erlang, "itb3_gleam_ffi", "set_memory_limit")
pub fn set_memory_limit(bytes: Int) -> Int

/// Sets the Go GC trigger percentage; returns the previous value. A
/// negative value queries without changing.
@external(erlang, "itb3_gleam_ffi", "set_gc_percent")
pub fn set_gc_percent(percent: Int) -> Int

/// Sets the Go runtime's GOMAXPROCS; returns the previous value. Zero
/// or a negative value queries without changing.
@external(erlang, "itb3_gleam_ffi", "set_gomaxprocs")
pub fn set_gomaxprocs(n: Int) -> Int

/// Writes the Go runtime's heap profile (pprof format) to `path`
/// after one forced garbage collection. An empty path falls back to
/// the ITB_MEMPROFILE environment variable; a path that is still
/// empty, or a file-system failure, is an error with status
/// "bad_input".
@external(erlang, "itb3_gleam_ffi", "write_heap_profile")
pub fn write_heap_profile(path: String) -> Result(Nil, ItbError)

/// Number of counter slots `pool_stats` returns. Size a reader from
/// this call, never from a constant.
@external(erlang, "itb3_gleam_ffi", "pool_stats_len")
pub fn pool_stats_len() -> Int

/// The library's pool hit / miss counters in slot order, as one list
/// of monotonically increasing totals since library load. Slot 0
/// carries the hash-array tier count `t`; tier `i` occupies the five
/// slots at `1 + 5*i` (starter width, get, new, regrow, new_bytes);
/// the scratch byte pool and the parallax chunk pool occupy the eight
/// slots at `1 + 5*t`. Differencing two snapshots gives the figures
/// of one measured window.
@external(erlang, "itb3_gleam_ffi", "pool_stats")
pub fn pool_stats() -> Result(List(Int), ItbError)
