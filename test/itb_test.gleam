//// Surface parity checks for the Gleam binding: version, Single
//// Message and stream round trips, save / load persistence, the
//// profile catalogue, the worker cap, opts pass-through, and error
//// mapping (unknown profile, tampered wire, freed handles). The
//// deep suite lives in Go under the shipped tree; the Erlang
//// backend's own suite covers the NIF shim.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import itb/pipeline.{type Pipeline}
import itb/stream
import itb_gleam.{ItbError}

@external(erlang, "crypto", "strong_rand_bytes")
fn rand_bytes(n: Int) -> BitArray

@external(erlang, "itb_gleam_ffi", "now_us")
fn now_us() -> Int

@external(erlang, "itb_gleam_ffi", "read_file")
fn read_file(path: String) -> Result(BitArray, String)

@external(erlang, "itb_gleam_ffi", "delete_file")
fn delete_file(path: String) -> Result(Nil, String)

@external(erlang, "itb_gleam_ffi", "flip_byte")
fn flip_byte(data: BitArray, position: Int) -> BitArray

const read_slice = 1_048_576

// ------------------------------------------------------------------
// Version
// ------------------------------------------------------------------

pub fn version_test() {
  let assert Ok(version) = itb_gleam.version()
  assert version != ""
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
  let assert Ok(blob) = pipeline.save(sender)
  assert bit_array.byte_size(blob) > 0
  let assert Ok(receiver) = pipeline.load(blob)
  #(sender, receiver)
}

pub fn save_load_round_trip_test() {
  let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(blob) = pipeline.save(sender)
  assert pipeline.save(sender) == Ok(blob)
  let assert Ok(receiver) = pipeline.load(blob)
  assert pipeline.save(receiver) == Ok(blob)
  let assert Ok(wire) =
    pipeline.encrypt_message(sender, <<"in-memory persist":utf8>>)
  assert pipeline.decrypt_message(receiver, wire)
    == Ok(<<"in-memory persist":utf8>>)
  pipeline.free(receiver)
  pipeline.free(sender)
}

pub fn save_f_load_f_round_trip_test() {
  let path = "/tmp/itb-gleam-persist-" <> int.to_string(now_us()) <> ".blob"
  let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(Nil) = pipeline.save_f(sender, path)
  let assert Ok(on_disk) = read_file(path)
  assert pipeline.save(sender) == Ok(on_disk)
  let assert Ok(receiver) = pipeline.load_f(path)
  assert pipeline.save(receiver) == pipeline.save(sender)
  let assert Ok(wire) = pipeline.encrypt_message(sender, <<"file persist":utf8>>)
  assert pipeline.decrypt_message(receiver, wire) == Ok(<<"file persist":utf8>>)
  let assert Error(ItbError("bad_input", _)) = pipeline.load_f(path <> ".absent")
  pipeline.free(receiver)
  pipeline.free(sender)
  let assert Ok(Nil) = delete_file(path)
  Nil
}

pub fn load_with_master_override_test() {
  let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
  let perm = <<0x31:size(256)>>
  let wrap = <<0x32:size(256)>>
  let assert Ok(rotated) = pipeline.rekey(sender, perm, wrap)
  let assert Ok(blob) = pipeline.save(sender)
  let assert Ok(receiver) = pipeline.load_with_masters(blob, perm, wrap)
  assert pipeline.save(receiver) == Ok(rotated)
  let assert Ok(wire) =
    pipeline.encrypt_message(sender, <<"master override":utf8>>)
  assert pipeline.decrypt_message(receiver, wire)
    == Ok(<<"master override":utf8>>)
  pipeline.free(receiver)
  pipeline.free(sender)
}

pub fn inspect_lookup_profiles_test() {
  let assert Ok(pipe) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(blob) = pipeline.save(pipe)
  pipeline.free(pipe)
  let assert Ok(record) = itb_gleam.inspect(blob)
  assert string.contains(record, "\"name\":\"singlemsg-triple-mac-v1\"")
  assert string.contains(record, "\"mode\":\"singlemsg-mac\"")
  assert itb_gleam.lookup("singlemsg-triple-mac-v1") == Ok(record)
  let assert Error(ItbError("bad_input", _)) =
    itb_gleam.inspect(<<"not a blob":utf8>>)
  let assert Error(ItbError("unknown_profile", _)) =
    itb_gleam.lookup("no-such-profile")
  let names = itb_gleam.profiles()
  assert list.contains(names, "singlemsg-triple-mac-v1")
  assert names == list.sort(names, string.compare)
  list.each(names, fn(name) {
    let assert Ok(r) = itb_gleam.lookup(name)
    assert string.contains(r, "\"name\":\"" <> name <> "\"")
  })
}

pub fn register_round_trip_test() {
  let profile =
    "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
    <> "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
    <> "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
    <> "\"keybits\":1024,\"parallax\":false,\"wrapper\":false}"
  let assert Ok(Nil) = itb_gleam.register("gleam-binding-test-mixed", profile)
  assert list.contains(itb_gleam.profiles(), "gleam-binding-test-mixed")
  let assert Ok(record) = itb_gleam.lookup("gleam-binding-test-mixed")
  assert string.contains(record, "\"hashes\":[\"blake3\"")
  let assert Error(ItbError("profile_exists", _)) =
    itb_gleam.register("gleam-binding-test-mixed", profile)
  // Strict record decode on the Go side: an unknown key is rejected
  // there, not by the binding.
  let assert Error(ItbError("bad_input", _)) =
    itb_gleam.register(
      "gleam-binding-test-badkey",
      "{\"mode\":\"singlemsg-nomac\",\"bogus\":1}",
    )
  let #(sender, receiver) = pair("gleam-binding-test-mixed")
  let plain = rand_bytes(8192)
  let assert Ok(wire) = pipeline.encrypt_message(sender, plain)
  assert pipeline.decrypt_message(receiver, wire) == Ok(plain)
  pipeline.free(receiver)
  pipeline.free(sender)
}

pub fn max_workers_test() {
  let assert Ok(pipe) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(Nil) = pipeline.max_workers(pipe, 2)
  // Clamped to auto / 256, never rejected.
  let assert Ok(Nil) = pipeline.max_workers(pipe, -1)
  let assert Ok(Nil) = pipeline.max_workers(pipe, 10_000)
  let assert Ok(wire) =
    pipeline.encrypt_message(pipe, <<"after cap change":utf8>>)
  assert pipeline.decrypt_message(pipe, wire) == Ok(<<"after cap change":utf8>>)
  pipeline.free(pipe)
  // A negative init-time cap is clamped as well.
  let assert Ok(neg) =
    pipeline.new("singlemsg-triple-mac-v1", [#("maxWorkers", "-1")])
  let assert Ok(w2) = pipeline.encrypt_message(neg, <<"negative cap":utf8>>)
  assert pipeline.decrypt_message(neg, w2) == Ok(<<"negative cap":utf8>>)
  pipeline.free(neg)
}

pub fn message_round_trip_test() {
  let #(sender, receiver) = pair("singlemsg-triple-mac-v1")
  let payloads = [
    <<0>>,
    <<"any text or binary data":utf8>>,
    rand_bytes(100_000),
  ]
  list.each(payloads, fn(plain) {
    let assert Ok(wire) = pipeline.encrypt_message(sender, plain)
    assert wire != plain
    let assert Ok(back) = pipeline.decrypt_message(receiver, wire)
    assert back == plain
  })
  pipeline.free(receiver)
  pipeline.free(sender)
}

pub fn empty_payload_rejected_test() {
  // Go core rejects zero-length plaintext uniformly with ErrEmptyInput
  // -> ItbError("bad_input", _) before any wire is produced. An empty
  // message has no cover story: it is always distinguishable at some
  // layer (wire length, timing, traffic count). Callers for whom an
  // empty signal is meaningful send a marker byte instead.
  let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Error(ItbError("bad_input", _)) =
    pipeline.encrypt_message(sender, <<>>)
  pipeline.free(sender)
}

pub fn opts_pass_through_test() {
  // Opts relay opaquely to Go; a No MAC profile with explicit shape
  // opts round-trips.
  let opts = [#("keyBits", "1024"), #("nonceBits", "512")]
  let assert Ok(sender) = pipeline.new("singlemsg-triple-nomac-v1", opts)
  let assert Ok(blob) = pipeline.save(sender)
  let assert Ok(receiver) = pipeline.load(blob)
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
  assert status == "unknown_profile"
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
    pipeline.load(<<"not a session blob":utf8>>)
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
  let assert Error(ItbError("bad_handle", _)) = pipeline.save(pipe)
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
