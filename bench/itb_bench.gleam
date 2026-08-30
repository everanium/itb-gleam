//// itb_bench — Message + Stream throughput micro-benchmarks.
////
//// Shapes:
////   message          encrypt_message throughput vs plaintext size
////                    (Single Message profile)
////   stream_pump      incremental encrypt session throughput (begin ->
////                    write 1 MiB slices, draining the spool after each
////                    write -> finish -> drain until finished -> free)
////   stream_one_shot  whole-buffer stream throughput (one
////                    encrypt_stream_one_shot / decrypt_stream_one_shot
////                    call per iteration; the FFI whole-buffer fast
////                    path for callers holding the full payload)
////
//// Sizes: 1 MiB / 16 MiB / 64 MiB; one table row per size.
////
//// Env-var overrides (defaults match the root Go BENCH3.md pin so
//// the numbers are directly comparable):
////
////   ITB_PROFILE        singlemsg-triple-nomac-v1 (message) /
////                      streaming-noaead-triple-v1 (stream)
////   ITB_INNER_HASH     areion512
////   ITB_KEY_BITS       1024
////   ITB_NONCE_BITS     512
////   ITB_WITH_PARALLAX  false
////   ITB_WITH_WRAPPER   false
////   ITB_BENCH_MIN_SEC  5
////
//// Invocation (from bindings/gleam, after ./build.sh; the source
//// lives in bench/ with a symlink in dev/ so the build tool picks
//// it up as a dev-profile module):
////
////   gleam run -m itb_bench -- [message|stream|all]

import gleam/bit_array
import gleam/float
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import itb/pipeline.{type Pipeline}
import itb/stream
import itb_gleam.{type Opts}

@external(erlang, "itb_gleam_ffi", "env")
fn env(name: String, default: String) -> String

@external(erlang, "itb_gleam_ffi", "now_us")
fn now_us() -> Int

@external(erlang, "itb_gleam_ffi", "argv")
fn argv() -> List(String)

@external(erlang, "crypto", "strong_rand_bytes")
fn rand_bytes(n: Int) -> BitArray

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> a

const min_iters = 3

const mib = 1_048_576

pub fn main() {
  // Bench-scale allocation churn leaks Go scratch heap unboundedly
  // without a soft memory cap + aggressive GC; the return values
  // report the previous settings, not an error.
  let _ = itb_gleam.set_memory_limit(536_870_912)
  let _ = itb_gleam.set_gc_percent(20)

  case argv() {
    ["message"] -> bench_message()
    ["stream"] -> bench_stream()
    ["stream_one_shot"] -> bench_stream_one_shot()
    [] | ["all"] -> {
      bench_message()
      bench_stream()
      bench_stream_one_shot()
    }
    _ -> {
      io.println_error(
        "usage: gleam run -m itb_bench -- "
        <> "[message|stream|stream_one_shot|all]",
      )
      halt(2)
    }
  }
}

// ------------------------------------------------------------------
// Shapes
// ------------------------------------------------------------------

fn bench_message() -> Nil {
  let profile = env("ITB_PROFILE", "singlemsg-triple-nomac-v1")
  let assert Ok(pipe) = pipeline.new(profile, bench_opts())
  header()
  list.each([mib, 16 * mib, 64 * mib], fn(size) {
    // CSPRNG-fill so plaintext content matches the root Go bench
    // (crypto/rand). Not in the timing loop.
    let plain = rand_bytes(size)
    bench_case("message", size, fn() {
      let assert Ok(_wire) = pipeline.encrypt_message(pipe, plain)
      Nil
    })
    // Pre-encrypt one wire outside the decrypt timing loop.
    let assert Ok(dec_wire) = pipeline.encrypt_message(pipe, plain)
    bench_case("message-dec", size, fn() {
      let assert Ok(_plain) = pipeline.decrypt_message(pipe, dec_wire)
      Nil
    })
  })
  pipeline.free(pipe)
}

fn bench_stream() -> Nil {
  let profile = env("ITB_PROFILE", "streaming-noaead-triple-v1")
  let assert Ok(pipe) = pipeline.new(profile, bench_opts())
  header()
  list.each([mib, 16 * mib, 64 * mib], fn(size) {
    let plain = rand_bytes(size)
    bench_case("stream_pump", size, fn() { pump(pipe, plain) })
    // Pre-encrypt one wire outside the decrypt timing loop.
    let dec_wire = pump_all(pipe, plain)
    bench_case("stream_pump-dec", size, fn() { pump_dec(pipe, dec_wire) })
  })
  pipeline.free(pipe)
}

// Whole-buffer stream: one FFI round trip through
// encrypt_stream_one_shot / decrypt_stream_one_shot per iteration.
fn bench_stream_one_shot() -> Nil {
  let profile = env("ITB_PROFILE", "streaming-noaead-triple-v1")
  let assert Ok(pipe) = pipeline.new(profile, bench_opts())
  header()
  list.each([mib, 16 * mib, 64 * mib], fn(size) {
    let plain = rand_bytes(size)
    bench_case("stream_one_shot", size, fn() {
      let assert Ok(_wire) = pipeline.encrypt_stream_one_shot(pipe, plain)
      Nil
    })
    // Pre-encrypt one wire outside the decrypt timing loop.
    let assert Ok(dec_wire) = pipeline.encrypt_stream_one_shot(pipe, plain)
    bench_case("stream_one_shot-dec", size, fn() {
      let assert Ok(_plain) = pipeline.decrypt_stream_one_shot(pipe, dec_wire)
      Nil
    })
  })
  pipeline.free(pipe)
}

// Full incremental encrypt session over one buffer.
fn pump(pipe: Pipeline, plain: BitArray) -> Nil {
  let assert Ok(session) = stream.encrypt(pipe)
  feed(session, plain)
  let assert Ok(Nil) = stream.finish(session)
  drain(session)
  stream.free(session)
}

fn feed(session: stream.Session, data: BitArray) -> Nil {
  case bit_array.byte_size(data) {
    0 -> Nil
    size -> {
      let n = int.min(size, mib)
      let assert Ok(slice) = bit_array.slice(data, 0, n)
      let assert Ok(rest) = bit_array.slice(data, n, size - n)
      let assert Ok(Nil) = stream.write(session, slice)
      // A read before end never blocks; drain whatever the chain has
      // produced so far to bound the Go-side spool.
      drain_ready(session)
      feed(session, rest)
    }
  }
}

fn drain_ready(session: stream.Session) -> Nil {
  let assert Ok(#(piece, finished)) = stream.read(session, mib)
  case bit_array.byte_size(piece) == 0 || finished {
    True -> Nil
    False -> drain_ready(session)
  }
}

fn drain(session: stream.Session) -> Nil {
  let assert Ok(#(_piece, finished)) = stream.read(session, mib)
  case finished {
    True -> Nil
    False -> drain(session)
  }
}

// Encrypt whole plain, collecting wire. Uses feed_noread so no
// encoder-produced bytes are lost to drain_ready's read-and-discard
// pattern: drain_ready's job in the `pump` shape is to bound the
// Go-side spool during a throwaway encrypt, so it reads chunks off
// the spool and drops them. In pump_all the wire needs to be
// preserved, so any drain_ready call landing after a real encoder
// chunk has been produced would silently drop that chunk. At small
// plaintext sizes (single-chunk plaintexts fitting in the 16 MiB
// DefaultChunkSize) the encoder emits nothing until stream_end and
// drain_ready during feed is a no-op — but at multi-chunk sizes
// (64 MiB and above) the encoder produces one output per full chunk
// consumed, and drain_ready between feed slices can catch and drop
// those chunks before drain_collect at end sees them.
//
// Go core wrapper-nonce batching fix (streams.go +
// wrapper.NewWrapWriter) closes the earlier wrapper-nonce
// split-write race so a single-chunk pump_all with plain feed would
// now produce a wire whose nonce is not stranded, but drain_ready's
// byte-dropping behaviour remains fundamentally incompatible with
// wire collection across chunk boundaries.
fn pump_all(pipe: Pipeline, plain: BitArray) -> BitArray {
  let assert Ok(session) = stream.encrypt(pipe)
  feed_noread(session, plain)
  let assert Ok(Nil) = stream.finish(session)
  let wire = drain_collect(session, <<>>)
  stream.free(session)
  wire
}

fn feed_noread(session: stream.Session, data: BitArray) -> Nil {
  case bit_array.byte_size(data) {
    0 -> Nil
    size -> {
      let n = int.min(size, mib)
      let assert Ok(slice) = bit_array.slice(data, 0, n)
      let assert Ok(rest) = bit_array.slice(data, n, size - n)
      let assert Ok(Nil) = stream.write(session, slice)
      feed_noread(session, rest)
    }
  }
}

fn drain_collect(session: stream.Session, acc: BitArray) -> BitArray {
  let assert Ok(#(piece, finished)) = stream.read(session, mib)
  let next = bit_array.concat([acc, piece])
  case finished {
    True -> next
    False -> drain_collect(session, next)
  }
}

fn pump_dec(pipe: Pipeline, wire: BitArray) -> Nil {
  let assert Ok(session) = stream.decrypt(pipe)
  feed(session, wire)
  let assert Ok(Nil) = stream.finish(session)
  drain(session)
  stream.free(session)
}

// ------------------------------------------------------------------
// Timing loop + env plumbing
// ------------------------------------------------------------------

fn header() -> Nil {
  io.println(
    string.pad_end("bench", 17, " ")
    <> " "
    <> string.pad_end("size", 8, " ")
    <> " mb_per_sec",
  )
}

// Timing loop: one untimed warm-up, then iterate until the
// wall-clock budget is spent (with an iteration floor); print one
// table row.
fn bench_case(name: String, size: Int, run: fn() -> Nil) -> Nil {
  // Warm-up.
  run()
  let budget = min_seconds()
  let start = now_us()
  let iters = loop(run, start, budget, 0)
  let elapsed = int.to_float(now_us() - start) /. 1_000_000.0
  let mb = int.to_float(size * iters) /. int.to_float(mib)
  io.println(
    string.pad_end(name, 17, " ")
    <> " "
    <> string.pad_end(size_label(size), 8, " ")
    <> " "
    <> format_1dp(mb /. elapsed),
  )
}

fn loop(run: fn() -> Nil, start: Int, budget: Float, iters: Int) -> Int {
  run()
  let elapsed = int.to_float(now_us() - start) /. 1_000_000.0
  case elapsed <. budget || iters + 1 < min_iters {
    True -> loop(run, start, budget, iters + 1)
    False -> iters + 1
  }
}

fn size_label(size: Int) -> String {
  case size >= mib {
    True -> int.to_string(size / mib) <> " MiB"
    False -> int.to_string(size / 1024) <> " KiB"
  }
}

fn format_1dp(value: Float) -> String {
  let scaled = float.round(value *. 10.0)
  int.to_string(scaled / 10) <> "." <> int.to_string(scaled % 10)
}

fn min_seconds() -> Float {
  let raw = env("ITB_BENCH_MIN_SEC", "5")
  let parsed =
    float.parse(raw)
    |> result.lazy_or(fn() { result.map(int.parse(raw), int.to_float) })
  case parsed {
    Ok(seconds) if seconds >. 0.0 -> seconds
    _ -> 5.0
  }
}

// Bench-shape opts from env (defaults per bindings/BENCH.md).
fn bench_opts() -> Opts {
  let base = [
    #("nonceBits", env("ITB_NONCE_BITS", "512")),
    #("keyBits", env("ITB_KEY_BITS", "1024")),
    #("withParallax", flag(env("ITB_WITH_PARALLAX", "false"))),
    #("withWrapper", flag(env("ITB_WITH_WRAPPER", "false"))),
  ]
  let base = case env("ITB_INNER_HASH", "") {
    "" -> base
    hash -> [#("innerHash", hash), ..base]
  }
  case env("ITB_MAC_NAME", "") {
    "" -> base
    mac -> [#("macName", mac), ..base]
  }
}

fn flag(raw: String) -> String {
  case raw {
    "true" | "1" -> "true"
    _ -> "false"
  }
}
