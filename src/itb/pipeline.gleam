//// itb/pipeline — Triple Pipeline sessions: lifecycle plus Single
//// Message encrypt / decrypt.
////
//// A `Pipeline` is an opaque NIF resource owned by the Erlang
//// backend: dropping every reference lets the garbage collector
//// release the Go-side state (libitb zeroes key material
//// internally), and `free` releases eagerly. Do not call `free` on
//// a handle another process is concurrently using — single-owner
//// discipline per handle, or drop references and let the collector
//// free.

import itb_gleam.{type ItbError, type Opts}

/// Opaque handle for a Triple Pipeline session (a NIF resource
/// reference at runtime).
pub type Pipeline

/// Constructs a fresh Pipeline against the named profile. Opts may
/// be the empty list for pure profile defaults. The session blob is
/// available through `save`.
@external(erlang, "itb_gleam_ffi", "init")
pub fn new(profile: String, opts: Opts) -> Result(Pipeline, ItbError)

/// Reconstructs a Pipeline from a blob produced by `save` / `rekey`,
/// using the blob-embedded masters. The blob's embedded profile
/// record is the sole structural source — no profile name, no opts.
pub fn load(blob: BitArray) -> Result(Pipeline, ItbError) {
  load_with_masters(blob, <<>>, <<>>)
}

/// As `load` with explicit master overrides. Both masters must be
/// supplied (a half-supplied pair is rejected Go-side); pass
/// `<<>>` / `<<>>` for the blob-embedded masters.
@external(erlang, "itb_gleam_ffi", "load")
pub fn load_with_masters(
  blob: BitArray,
  perm_master: BitArray,
  wrap_master: BitArray,
) -> Result(Pipeline, ItbError)

/// `load` for a blob stored in a file; the file is read inside the
/// library.
pub fn load_f(path: String) -> Result(Pipeline, ItbError) {
  load_f_with_masters(path, <<>>, <<>>)
}

/// As `load_f` with explicit master overrides.
@external(erlang, "itb_gleam_ffi", "load_f")
pub fn load_f_with_masters(
  path: String,
  perm_master: BitArray,
  wrap_master: BitArray,
) -> Result(Pipeline, ItbError)

/// The current serialised session blob — the bytes `new` produced,
/// the bytes `load` re-marshalled, or the bytes of the latest
/// `rekey`.
@external(erlang, "itb_gleam_ffi", "save")
pub fn save(pipeline: Pipeline) -> Result(BitArray, ItbError)

/// Writes the current session blob to `path` inside the library
/// (mode 0600; the containing directory must exist).
@external(erlang, "itb_gleam_ffi", "save_f")
pub fn save_f(pipeline: Pipeline, path: String) -> Result(Nil, ItbError)

/// Sets the worker cap for every subsequent cipher call. `n` is
/// clamped, never rejected: `n <= 0` selects auto, `1..256` pins the
/// cap, larger values are treated as 256. The cap is per-machine
/// tuning and is never written to the blob.
@external(erlang, "itb_gleam_ffi", "max_workers")
pub fn max_workers(pipeline: Pipeline, n: Int) -> Result(Nil, ItbError)

/// Rotates the parallax + wrapper masters and returns the refreshed
/// session blob (also observable through `save`). Must not run
/// concurrently with cipher calls or open stream sessions on the
/// same Pipeline.
@external(erlang, "itb_gleam_ffi", "rekey")
pub fn rekey(
  pipeline: Pipeline,
  perm_master: BitArray,
  wrap_master: BitArray,
) -> Result(BitArray, ItbError)

/// Eagerly closes (zeroing key material Go-side) and releases the
/// handle. Idempotent; subsequent calls on the handle fail with
/// status "bad_handle". Garbage collection of the last reference is
/// the release backstop.
@external(erlang, "itb_gleam_ffi", "free")
pub fn free(pipeline: Pipeline) -> Nil

/// One call, one self-contained wire.
@external(erlang, "itb_gleam_ffi", "encrypt_message")
pub fn encrypt_message(
  pipeline: Pipeline,
  plain: BitArray,
) -> Result(BitArray, ItbError)

/// Receive-side counterpart of `encrypt_message`.
@external(erlang, "itb_gleam_ffi", "decrypt_message")
pub fn decrypt_message(
  pipeline: Pipeline,
  wire: BitArray,
) -> Result(BitArray, ItbError)

/// One-shot stream encrypt for callers holding the whole plaintext
/// in memory: a single call through the Pipeline's stream chain. For
/// bounded-memory streaming use the incremental `itb/stream` session.
@external(erlang, "itb_gleam_ffi", "encrypt_stream_one_shot")
pub fn encrypt_stream_one_shot(
  pipeline: Pipeline,
  plain: BitArray,
) -> Result(BitArray, ItbError)

/// Receive-side counterpart of `encrypt_stream_one_shot`.
@external(erlang, "itb_gleam_ffi", "decrypt_stream_one_shot")
pub fn decrypt_stream_one_shot(
  pipeline: Pipeline,
  wire: BitArray,
) -> Result(BitArray, ItbError)
