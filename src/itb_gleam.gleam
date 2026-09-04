//// itb_gleam — public entry point of the ITB Gleam binding.
////
//// Thin proxy over the ITB Erlang binding's Triple Pipeline surface
//// (bindings/erlang, module `itb`) via native BEAM bytecode interop
//// — the Gleam layer calls the Erlang module directly through the
//// shape-normalising FFI adapter (src/itb_gleam_ffi.erl) and adds no
//// FFI hop of its own. The only native code in the stack is the
//// Erlang binding's NIF shim. No ITB construction logic lives in
//// this binding: profile names, opts keys, and every primitive name
//// are opaque strings passed through to Go for validation.
////
//// The top-level module is named `itb_gleam` rather than `itb`
//// because the BEAM module name `itb` belongs to the Erlang backend
//// this binding proxies; the pipeline / stream surface lives under
//// `itb/pipeline` and `itb/stream`.
////
//// Quick start:
////
////     import itb/pipeline
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

/// Failure surfaced by a libitb call: the C binding's status table
/// entry as a string plus the Go-side diagnostic text.
pub type ItbError {
  ItbError(status: String, detail: String)
}

/// Opts accumulate into the URL-query string consumed by libitb;
/// the binding performs no validation — Go rejects unknown keys and
/// bad values with a diagnostic in the error detail.
pub type Opts =
  List(#(String, String))

/// The libitb library version string (e.g. "0.4.1").
@external(erlang, "itb_gleam_ffi", "version")
pub fn version() -> Result(String, ItbError)

/// Decodes the blob's embedded profile record without opening a
/// Pipeline and returns it as the JSON text libitb emits (keys
/// `name`, `mode`, `width`, `hash`, `hashes`, `keybits`, `mac`,
/// `tagstub`, `chunk`, `wrapper`, `outer`, `parallax`, `palette`,
/// `segment`; absent keys are optional fields at their zero value).
/// No registry read, no primitive probe.
@external(erlang, "itb_gleam_ffi", "inspect")
pub fn inspect(blob: BitArray) -> Result(String, ItbError)

/// Registers a profile record under `name` so subsequent
/// `pipeline.new` / `lookup` calls resolve it. `profile_json` is the
/// record as JSON text — the shape `inspect` / `lookup` return; a
/// `name` key inside it, if present, must be empty or equal to
/// `name`. Validation is performed by libitb; a duplicate name fails
/// with status "profile_exists".
@external(erlang, "itb_gleam_ffi", "register")
pub fn register(name: String, profile_json: String) -> Result(Nil, ItbError)

/// The profile record registered under `name` (a shipped catalogue
/// entry or a prior `register`) as JSON text. An unknown name fails
/// with status "unknown_profile".
@external(erlang, "itb_gleam_ffi", "lookup")
pub fn lookup(name: String) -> Result(String, ItbError)

/// The sorted list of every registered profile name.
@external(erlang, "itb_gleam_ffi", "profiles")
pub fn profiles() -> List(String)

/// The Go-side diagnostic recorded by the most recent failing libitb
/// call (process-global last-write-wins; "" when none). The error
/// values already carry this detail — direct use is for ad-hoc
/// debugging only.
@external(erlang, "itb_gleam_ffi", "last_error")
pub fn last_error() -> String

/// Sets the Go runtime's soft heap limit in bytes; returns the
/// previous limit. A negative value queries without changing.
@external(erlang, "itb_gleam_ffi", "set_memory_limit")
pub fn set_memory_limit(bytes: Int) -> Int

/// Sets the Go GC trigger percentage; returns the previous value. A
/// negative value queries without changing.
@external(erlang, "itb_gleam_ffi", "set_gc_percent")
pub fn set_gc_percent(percent: Int) -> Int
