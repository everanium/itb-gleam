//// Surface parity checks for the Gleam binding: version, canonical
//// hash roster order, Single Message and stream round trips, opts
//// pass-through, and error mapping (unknown profile, tampered wire,
//// freed handles). The deep suite lives in Go under the shipped
//// tree; the Erlang backend's own suite covers the NIF shim.

import gleam/bit_array
import gleam/int
import gleam/list
import itb/pipeline.{type Pipeline}
import itb/stream
import itb_gleam.{ItbError}

@external(erlang, "crypto", "strong_rand_bytes")
fn rand_bytes(n: Int) -> BitArray

@external(erlang, "itb_gleam_ffi", "flip_byte")
fn flip_byte(data: BitArray, position: Int) -> BitArray

const read_slice = 1_048_576

// ------------------------------------------------------------------
// Version + roster
// ------------------------------------------------------------------

pub fn version_test() {
  let assert Ok(version) = itb_gleam.version()
  assert version != ""
}

pub fn hashes_canonical_order_test() {
  // Exact roster in canonical registry order (test fixture mirrors
  // the Go-side registry, the single source of truth).
  assert itb_gleam.hashes()
    == [
      #("areion256", 256),
      #("areion512", 512),
      #("blake2b256", 256),
      #("blake2b512", 512),
      #("blake2s", 256),
      #("blake3", 256),
      #("aescmac", 128),
      #("siphash24", 128),
      #("chacha20", 256),
    ]
}

pub fn runtime_knobs_test() {
  // Negative values query without changing; the return is the
  // previous setting.
  let previous = itb_gleam.set_memory_limit(-1)
  assert previous == itb_gleam.set_memory_limit(-1)
  let _ = itb_gleam.set_gc_percent(-2)
  Nil
}

// ------------------------------------------------------------------
// Single Message round trip
// ------------------------------------------------------------------

fn pair(profile: String) -> #(Pipeline, Pipeline) {
  let assert Ok(sender) = pipeline.new(profile, [])
  let assert Ok(blob) = pipeline.blob(sender)
  assert bit_array.byte_size(blob) > 0
  let assert Ok(receiver) = pipeline.open(profile, blob, [])
  #(sender, receiver)
}

pub fn message_round_trip_test() {
  let #(sender, receiver) = pair("singlemsg-triple-mac-v1")
  let payloads = [
    <<>>,
    <<0>>,
    <<"any text or binary data":utf8>>,
    rand_bytes(100_000),
  ]
  list.each(payloads, fn(plain) {
    let assert Ok(wire) = pipeline.encrypt_message(sender, plain)
    assert plain == <<>> || wire != plain
    let assert Ok(back) = pipeline.decrypt_message(receiver, wire)
    assert back == plain
  })
  pipeline.free(receiver)
  pipeline.free(sender)
}

pub fn opts_pass_through_test() {
  // Opts relay opaquely to Go; a No MAC profile with explicit shape
  // opts round-trips.
  let opts = [#("keyBits", "1024"), #("nonceBits", "512")]
  let assert Ok(sender) = pipeline.new("singlemsg-triple-nomac-v1", opts)
  let assert Ok(blob) = pipeline.blob(sender)
  let assert Ok(receiver) = pipeline.open("singlemsg-triple-nomac-v1", blob, [])
  let plain = rand_bytes(4096)
  let assert Ok(wire) = pipeline.encrypt_message(sender, plain)
  let assert Ok(back) = pipeline.decrypt_message(receiver, wire)
  assert back == plain
  pipeline.free(receiver)
  pipeline.free(sender)
}

// ------------------------------------------------------------------
// Stream round trip (Non-AEAD streaming profile)
// ------------------------------------------------------------------

pub fn stream_round_trip_test() {
  let #(sender, receiver) = pair("streaming-noaead-triple-v1")
  // A non-round size so the chunk loop exercises a short tail.
  let plain = rand_bytes(262_151)
  let wire = run_session(stream.encrypt, sender, plain, 60_000)
  assert wire != plain
  let back = run_session(stream.decrypt, receiver, wire, 65_536)
  assert back == plain
  pipeline.free(receiver)
  pipeline.free(sender)
}

fn run_session(
  begin: fn(Pipeline) -> Result(stream.Session, itb_gleam.ItbError),
  pipe: Pipeline,
  data: BitArray,
  chunk: Int,
) -> BitArray {
  let assert Ok(session) = begin(pipe)
  feed(session, data, chunk)
  let assert Ok(Nil) = stream.finish(session)
  let out = drain(session, <<>>)
  stream.free(session)
  out
}

fn feed(session: stream.Session, data: BitArray, chunk: Int) -> Nil {
  case bit_array.byte_size(data) {
    0 -> Nil
    size -> {
      let n = int.min(size, chunk)
      let assert Ok(slice) = bit_array.slice(data, 0, n)
      let assert Ok(rest) = bit_array.slice(data, n, size - n)
      let assert Ok(Nil) = stream.write(session, slice)
      feed(session, rest, chunk)
    }
  }
}

fn drain(session: stream.Session, acc: BitArray) -> BitArray {
  let assert Ok(#(piece, finished)) = stream.read(session, read_slice)
  let acc = bit_array.append(acc, piece)
  case finished {
    True -> acc
    False -> drain(session, acc)
  }
}

// ------------------------------------------------------------------
// One-shot stream round trip (Streaming AEAD profile)
// ------------------------------------------------------------------

pub fn stream_one_shot_round_trip_test() {
  let #(sender, receiver) = pair("streaming-aead-triple-mac-v1")
  let plain = rand_bytes(262_151)
  // One-shot both ways, then cross-check against the incremental
  // session path in each direction.
  let assert Ok(wire) = pipeline.encrypt_stream_one_shot(sender, plain)
  assert bit_array.byte_size(wire) > bit_array.byte_size(plain)
  let assert Ok(back) = pipeline.decrypt_stream_one_shot(receiver, wire)
  assert back == plain
  assert run_session(stream.decrypt, receiver, wire, 65_536) == plain
  let wire2 = run_session(stream.encrypt, sender, plain, 60_000)
  let assert Ok(back2) = pipeline.decrypt_stream_one_shot(receiver, wire2)
  assert back2 == plain
  pipeline.free(receiver)
  pipeline.free(sender)
}

// ------------------------------------------------------------------
// Error mapping
// ------------------------------------------------------------------

pub fn unknown_profile_test() {
  let assert Error(ItbError(status, detail)) =
    pipeline.new("no-such-profile", [])
  assert status == "bad_input"
  assert detail != ""
}

pub fn unknown_opts_key_test() {
  // Typoed lowercase s — the binding performs no key validation of
  // its own; Go rejects the unknown key.
  let assert Error(ItbError("bad_input", _)) =
    pipeline.new("singlemsg-triple-mac-v1", [#("chunksize", "4096")])
  Nil
}

pub fn malformed_blob_test() {
  let assert Error(ItbError(_, _)) =
    pipeline.open("singlemsg-triple-mac-v1", <<"not a session blob":utf8>>, [])
  Nil
}

pub fn tampered_wire_test() {
  // A bit flip in authenticated wire content fails with mac_failure.
  // A single flip can land in the container's CSPRNG residue — where
  // the decrypt legitimately completes clean — or fail structurally
  // in the envelope framing, so successive flip positions are probed
  // until one lands in authenticated content.
  let #(sender, receiver) = pair("singlemsg-triple-mac-v1")
  let plain = rand_bytes(4096)
  let assert Ok(wire) = pipeline.encrypt_message(sender, plain)
  assert probe_flip(receiver, wire, 0, bit_array.byte_size(wire))
  pipeline.free(receiver)
  pipeline.free(sender)
}

fn probe_flip(
  receiver: Pipeline,
  wire: BitArray,
  position: Int,
  limit: Int,
) -> Bool {
  case position >= limit {
    True -> False
    False ->
      case pipeline.decrypt_message(receiver, flip_byte(wire, position)) {
        Error(ItbError("mac_failure", _)) -> True
        _ -> probe_flip(receiver, wire, position + 1, limit)
      }
  }
}

pub fn freed_pipeline_test() {
  let assert Ok(pipe) = pipeline.new("singlemsg-triple-mac-v1", [])
  pipeline.free(pipe)
  // Idempotent.
  pipeline.free(pipe)
  let assert Error(ItbError("bad_handle", _)) =
    pipeline.encrypt_message(pipe, <<1>>)
  let assert Error(ItbError("bad_handle", _)) = pipeline.blob(pipe)
  let assert Error(ItbError("bad_handle", _)) = stream.encrypt(pipe)
  Nil
}

pub fn freed_stream_test() {
  let assert Ok(pipe) = pipeline.new("streaming-noaead-triple-v1", [])
  let assert Ok(session) = stream.encrypt(pipe)
  stream.free(session)
  // Idempotent.
  stream.free(session)
  let assert Error(ItbError("bad_handle", _)) = stream.write(session, <<1>>)
  let assert Error(ItbError("bad_handle", _)) = stream.finish(session)
  let assert Error(ItbError("bad_handle", _)) = stream.read(session, 16)
  pipeline.free(pipe)
}
