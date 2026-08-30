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
/// be the empty list for pure profile defaults.
@external(erlang, "itb_gleam_ffi", "init")
pub fn new(profile: String, opts: Opts) -> Result(Pipeline, ItbError)

/// Reconstructs a Pipeline from a blob produced by a sender's
/// `new` / `rekey`, using the blob-embedded masters.
pub fn open(
  profile: String,
  blob: BitArray,
  opts: Opts,
) -> Result(Pipeline, ItbError) {
  open_with_masters(profile, blob, opts, <<>>, <<>>)
}

/// As `open` with explicit master overrides. Both masters must be
/// supplied non-empty (a half-supplied pair is rejected); pass
/// `<<>>` / `<<>>` for the blob-embedded masters.
@external(erlang, "itb_gleam_ffi", "open")
pub fn open_with_masters(
  profile: String,
  blob: BitArray,
  opts: Opts,
  perm_master: BitArray,
  wrap_master: BitArray,
) -> Result(Pipeline, ItbError)

/// The exported session-bundle blob for the receiver side; refreshed
/// by `rekey`.
@external(erlang, "itb_gleam_ffi", "blob")
pub fn blob(pipeline: Pipeline) -> Result(BitArray, ItbError)

/// Rotates the parallax + wrapper masters and refreshes the blob.
/// Must not run concurrently with cipher calls or open stream
/// sessions on the same Pipeline.
@external(erlang, "itb_gleam_ffi", "rekey")
pub fn rekey(
  pipeline: Pipeline,
  perm_master: BitArray,
  wrap_master: BitArray,
) -> Result(Nil, ItbError)

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
