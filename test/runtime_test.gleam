//// The runtime-shaping knobs and the hash-registry enumeration: the
//// GOMAXPROCS setter and its query form, the heap-profile writer on a
//// good and on a rejected path, the pool-counter vector and its
//// length query, and the registry names `pipeline.new` accepts under
//// `innerHash`. Every entry delegates through the FFI adapter to the
//// Erlang binding's `itb3` module — `itb3:set_gomaxprocs/1`,
//// `itb3:write_heap_profile/1`, `itb3:pool_stats_len/0`,
//// `itb3:pool_stats/0`, `itb3:hash_names/0`.

import gleam/list
import itb3/pipeline
import itb3_gleam.{ItbError}

@external(erlang, "filelib", "is_regular")
fn is_regular(path: String) -> Bool

@external(erlang, "file", "delete")
fn delete_file(path: String) -> Result(Nil, a)

@external(erlang, "filelib", "file_size")
fn file_size(path: String) -> Int

const profile_path = "/tmp/itb-gleam-heap.pprof"

// Zero or a negative value queries without changing, so the query is
// repeatable and the round trip restores what was in force.
pub fn set_gomaxprocs_test() {
  let before = itb3_gleam.set_gomaxprocs(0)
  assert before > 0
  assert itb3_gleam.set_gomaxprocs(0) == before
  assert itb3_gleam.set_gomaxprocs(2) == before
  assert itb3_gleam.set_gomaxprocs(0) == 2
  assert itb3_gleam.set_gomaxprocs(before) == 2
  assert itb3_gleam.set_gomaxprocs(0) == before
}

pub fn write_heap_profile_test() {
  let assert Ok(Nil) = itb3_gleam.write_heap_profile(profile_path)
  assert is_regular(profile_path)
  assert file_size(profile_path) > 0
  let _ = delete_file(profile_path)
  Nil
}

// A path that cannot be created is rejected, and the diagnostic the
// library composed comes back with the status.
pub fn write_heap_profile_rejects_bad_path_test() {
  let assert Error(ItbError(status, detail)) =
    itb3_gleam.write_heap_profile("/tmp/no-such-directory/heap.pprof")
  assert status == "bad_input"
  assert detail != ""
}

// The slot count is read from the library, and the vector it fills
// matches that count; slot 0 carries the tier count and the layout
// 1 + 5*t + 8 follows from it.
pub fn pool_stats_test() {
  let len = itb3_gleam.pool_stats_len()
  assert len > 0
  let assert Ok(slots) = itb3_gleam.pool_stats()
  assert list.length(slots) == len
  let assert [tiers, ..] = slots
  assert tiers > 0
  assert len == 1 + 5 * tiers + 8
  assert list.all(slots, fn(v) { v >= 0 })
}

// The counters are monotonic totals since library load, so a cipher
// call between two snapshots can only move them upward.
pub fn pool_stats_monotonic_test() {
  let assert Ok(before) = itb3_gleam.pool_stats()
  let assert Ok(pipe) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(_wire) = pipeline.encrypt_message(pipe, <<"payload":utf8>>)
  pipeline.free(pipe)
  let assert Ok(later) = itb3_gleam.pool_stats()
  assert list.length(before) == list.length(later)
  assert list.all(list.zip(before, later), fn(p) { p.1 >= p.0 })
}

// Every registry name is accepted as an inner hash, which is what
// makes the enumeration usable for validating a primitive name.
pub fn hash_names_test() {
  let names = itb3_gleam.hash_names()
  assert names != []
  assert list.contains(names, "areion512")
  assert list.unique(names) == names
  list.each(names, fn(name) {
    let assert Ok(pipe) =
      pipeline.new("singlemsg-triple-nomac-v1", [#("innerHash", name)])
    pipeline.free(pipe)
  })
}

pub fn hash_names_rejects_unregistered_test() {
  assert !list.contains(itb3_gleam.hash_names(), "no-such-primitive")
  let assert Error(_) =
    pipeline.new("singlemsg-triple-nomac-v1", [
      #("innerHash", "no-such-primitive"),
    ])
  Nil
}

// Every status name an ItbError can carry resolves to the numeric
// code the C ABI assigns it, and a name outside the table resolves to
// the internal-error code.
pub fn status_code_test() {
  assert itb3_gleam.status_code("ok") == 0
  assert itb3_gleam.status_code("bad_input") == 4
  assert itb3_gleam.status_code("mac_failure") == 10
  assert itb3_gleam.status_code("unknown_profile") == 13
  assert itb3_gleam.status_code("profile_exists") == 26
  assert itb3_gleam.status_code("internal") == 99
  assert itb3_gleam.status_code("no_such_status") == 99

  // The codes are distinct, so a diagnostic naming one names it
  // unambiguously.
  let known = [
    "ok", "bad_hash", "bad_key_bits", "bad_handle", "bad_input",
    "buffer_too_small", "encrypt_failed", "decrypt_failed", "seed_width_mix",
    "bad_mac", "mac_failure", "blob_malformed_recipe",
    "recipe_primitive_unknown", "unknown_profile", "blob_mode_mismatch",
    "blob_malformed", "blob_version_too_new", "blob_too_many_opts",
    "stream_truncated", "stream_after_final", "triple_closed",
    "profile_exists",
  ]
  let codes = list.map(known, itb3_gleam.status_code)
  assert list.unique(codes) == codes
}

// The status a failing call hands back resolves through the same
// accessor, so the pair (status, code) is attributable to one call.
pub fn status_code_of_failing_call_test() {
  let assert Error(ItbError(status, _detail)) =
    itb3_gleam.lookup("no-such-profile")
  assert status == "unknown_profile"
  assert itb3_gleam.status_code(status) == 13
}
