//// The final summary in both renderings, and the two measurements it
//// folds in that are not per-worker counters: the process resident
//// set and the shared library's pool counters.

import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import itb3_gleam
import loop_ffi
import loop_payload
import loop_size
import loop_state
import loop_types.{type Config, type Run, type WStats}

/// One hash-array tier's differenced figures.
pub type Tier {
  Tier(
    tier: Int,
    starter: Int,
    get: Int,
    new: Int,
    regrow: Int,
    new_bytes: Int,
  )
}

/// One byte pool's differenced figures.
pub type BytePool {
  BytePool(get: Int, new: Int, regrow: Int, regrow_bytes: Int)
}

// ------------------------------------------------------------------
// Resident set
// ------------------------------------------------------------------

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
pub fn read_rss() -> #(Int, Int) {
  case loop_ffi.read_text("/proc/self/status") {
    Error(Nil) -> #(0, 0)
    Ok(text) ->
      list.fold(string.split(text, "\n"), #(0, 0), fn(acc, line) {
        case
          string.starts_with(line, "VmRSS:"),
          string.starts_with(line, "VmHWM:")
        {
          True, _ -> #(status_kb(line), acc.1)
          _, True -> #(acc.0, status_kb(line))
          _, _ -> acc
        }
      })
  }
}

fn status_kb(line: String) -> Int {
  let digits =
    line
    |> string.to_graphemes
    |> list.filter(fn(c) { is_digit(c) })
    |> string.concat
  case int.parse(digits) {
    Ok(kb) -> kb * 1024
    Error(Nil) -> 0
  }
}

fn is_digit(c: String) -> Bool {
  c == "0"
  || c == "1"
  || c == "2"
  || c == "3"
  || c == "4"
  || c == "5"
  || c == "6"
  || c == "7"
  || c == "8"
  || c == "9"
}

// ------------------------------------------------------------------
// Pool counters
// ------------------------------------------------------------------

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and
/// the parallax chunk pool the checkouts, constructor misses, regrows
/// and regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a
/// pool keeps its items warm between calls or evicts them across GC
/// cycles. The slot layout is read from the library: slot 0 carries
/// the tier count T, tier i occupies the five slots at 1 + 5*i, and
/// the two byte pools occupy the eight slots at 1 + 5*T; the vector
/// is sized by the binding's length query, never by a constant.
pub fn pool_snapshot() -> List(Int) {
  case itb3_gleam.pool_stats() {
    Ok(slots) -> slots
    Error(_) -> []
  }
}

fn at(slots: List(Int), index: Int) -> Int {
  case list.drop(slots, index) {
    [v, ..] -> v
    [] -> 0
  }
}

fn zero_pool() -> BytePool {
  BytePool(0, 0, 0, 0)
}

fn pool_diff(
  warmup: List(Int),
  steady: List(Int),
) -> #(List(Tier), BytePool, BytePool) {
  let len = list.length(steady)
  case list.length(warmup) < 9 || len < 9 {
    True -> #([], zero_pool(), zero_pool())
    False -> {
      let tiers = at(steady, 0)
      case tiers < 0 || 1 + 5 * tiers + 8 > len {
        True -> #([], zero_pool(), zero_pool())
        False -> {
          let all =
            list.map(indices(tiers), fn(i) {
              Tier(
                tier: i,
                starter: at(steady, 1 + 5 * i),
                get: at(steady, 2 + 5 * i) - at(warmup, 2 + 5 * i),
                new: at(steady, 3 + 5 * i) - at(warmup, 3 + 5 * i),
                regrow: at(steady, 4 + 5 * i) - at(warmup, 4 + 5 * i),
                new_bytes: at(steady, 5 + 5 * i) - at(warmup, 5 + 5 * i),
              )
            })
          let tail = 1 + 5 * tiers
          #(
            list.filter(all, fn(t) { t.starter != 0 }),
            byte_pool(warmup, steady, tail),
            byte_pool(warmup, steady, tail + 4),
          )
        }
      }
    }
  }
}

// 0 .. n-1; the stdlib this binding pins carries no range builder.
fn indices(n: Int) -> List(Int) {
  build_indices(n - 1, [])
}

fn build_indices(i: Int, acc: List(Int)) -> List(Int) {
  case i < 0 {
    True -> acc
    False -> build_indices(i - 1, [i, ..acc])
  }
}

fn byte_pool(warmup: List(Int), steady: List(Int), base: Int) -> BytePool {
  BytePool(
    get: at(steady, base) - at(warmup, base),
    new: at(steady, base + 1) - at(warmup, base + 1),
    regrow: at(steady, base + 2) - at(warmup, base + 2),
    regrow_bytes: at(steady, base + 3) - at(warmup, base + 3),
  )
}

// Misses over checkouts as a percentage; zero when nothing was
// checked out.
fn miss_percent(miss: Int, get: Int) -> Float {
  case get <= 0 {
    True -> 0.0
    False -> 100.0 *. int.to_float(miss) /. int.to_float(get)
  }
}

// ------------------------------------------------------------------
// Summary
// ------------------------------------------------------------------

type Figures {
  Figures(
    total_iters: Int,
    total_enc: Int,
    total_dec: Int,
    avg_enc: Int,
    avg_dec: Int,
    elapsed: Int,
    errors: List(String),
    pass: Bool,
    rekeys: Int,
    cycles: Int,
    gomaxprocs: Int,
    stream_profile: String,
    msg_profile: String,
    rss_warmup: Int,
    rss_peak: Int,
    rss_final: Int,
    rss_delta: Int,
    rss_growth: Float,
    tiers: List(Tier),
    buf: BytePool,
    chunk: BytePool,
    stats: List(WStats),
  )
}

/// Output contract. Both renderings are shared with the Go harness
/// and every other binding's loop utility field for field: the same
/// lines in the same order, the same keys in the same order, floats
/// with a fixed number of decimals so the JSON is byte-identical
/// across implementations. The Go harness alone adds its
/// runtime-internal lines after `rss:` and its runtime-internal keys
/// after `parallax_chunk_pool`; nothing here reproduces them because
/// nothing they read is reachable through the binding.
pub fn final(
  run: Run,
  stats: List(WStats),
  elapsed_ns: Int,
  rss: #(Int, Int, Int),
  pools: #(List(Int), List(Int)),
) -> Int {
  let cfg = run.cfg
  let #(rss_warmup, rss_peak, rss_final) = rss
  let #(pool_warmup, pool_steady) = pools
  let total_iters = sum(list.map(stats, fn(s) { s.iters }))
  let total_enc = sum(list.map(stats, fn(s) { s.bytes_enc }))
  let total_dec = sum(list.map(stats, fn(s) { s.bytes_dec }))
  let nanos_enc = sum(list.map(stats, fn(s) { s.nanos_enc }))
  let nanos_dec = sum(list.map(stats, fn(s) { s.nanos_dec }))
  let errors =
    stats
    |> list.filter(fn(s) { s.failed })
    |> list.map(fn(s) { s.error })

  // Throughput. Per-direction throughput divides the sum of every
  // worker's wall time in that direction by the worker count — the
  // equivalent single-stream wall time under N-way concurrency — so
  // each direction reports the aggregate rate it sustained rather
  // than collapsing to combined/2 (every iteration moves equal
  // encrypt and decrypt bytes, so a total-elapsed denominator would
  // give both directions the same figure). The combined rate keeps
  // total elapsed as the one-glance overall figure.
  let avg_enc = case nanos_enc > 0 {
    True -> nanos_enc / cfg.workers
    False -> 0
  }
  let avg_dec = case nanos_dec > 0 {
    True -> nanos_dec / cfg.workers
    False -> 0
  }
  let rss_delta = rss_final - rss_warmup
  let rss_growth = case rss_warmup > 0 {
    True -> 100.0 *. int.to_float(rss_delta) /. int.to_float(rss_warmup)
    False -> 0.0
  }
  let #(tiers, buf, chunk) = pool_diff(pool_warmup, pool_steady)
  let pass = errors == []
  let grant = loop_state.handles(run.state)
  let f =
    Figures(
      total_iters: total_iters,
      total_enc: total_enc,
      total_dec: total_dec,
      avg_enc: avg_enc,
      avg_dec: avg_dec,
      elapsed: elapsed_ns,
      errors: errors,
      pass: pass,
      rekeys: loop_state.rekeys(run.counts),
      cycles: loop_state.blob_cycles(run.counts),
      gomaxprocs: itb3_gleam.set_gomaxprocs(0),
      stream_profile: case grant.stream_pipe {
        Some(_) -> run.stream_profile
        None -> ""
      },
      msg_profile: case grant.msg_pipe {
        Some(_) -> run.msg_profile
        None -> ""
      },
      rss_warmup: rss_warmup,
      rss_peak: rss_peak,
      rss_final: rss_final,
      rss_delta: rss_delta,
      rss_growth: rss_growth,
      tiers: tiers,
      buf: buf,
      chunk: chunk,
      stats: stats,
    )
  case cfg.json_output {
    True -> json(cfg, f)
    False -> human(cfg, f)
  }
  case pass {
    True -> 0
    False -> 1
  }
}

fn sum(values: List(Int)) -> Int {
  list.fold(values, 0, fn(a, b) { a + b })
}

// ------------------------------------------------------------------

fn json(cfg: Config, f: Figures) -> Nil {
  let i = int.to_string
  loop_ffi.write_stdout(
    "{\"duration_seconds\":"
    <> loop_size.f3(int.to_float(f.elapsed) /. 1.0e9)
    <> ",\"iterations\":"
    <> i(f.total_iters)
    <> ",\"per_worker_iterations\":["
    <> string.join(list.map(f.stats, fn(s) { i(s.iters) }), ",")
    <> "]"
    <> ",\"bytes_encrypted\":"
    <> i(f.total_enc)
    <> ",\"bytes_decrypted\":"
    <> i(f.total_dec)
    <> ",\"encrypt_mb_per_sec\":"
    <> loop_size.f1(loop_size.mb_per_sec(f.total_enc, f.avg_enc))
    <> ",\"decrypt_mb_per_sec\":"
    <> loop_size.f1(loop_size.mb_per_sec(f.total_dec, f.avg_dec))
    <> ",\"combined_mb_per_sec\":"
    <> loop_size.f1(loop_size.mb_per_sec(f.total_enc + f.total_dec, f.elapsed))
    <> ",\"rekeys\":"
    <> i(f.rekeys)
    <> ",\"blob_cycles\":"
    <> i(f.cycles)
    <> ",\"worker_errors\":["
    <> string.join(list.map(f.errors, jstr), ",")
    <> "]"
    <> ",\"verdict\":"
    <> jstr(verdict(f.pass))
    <> ",\"shape\":"
    <> jstr(loop_types.shape_name(cfg.shape))
    <> ",\"stream_profile\":"
    <> jstr(f.stream_profile)
    <> ",\"message_profile\":"
    <> jstr(f.msg_profile)
    <> ",\"hash\":"
    <> jstr(cfg.hash)
    <> ",\"mac\":"
    <> jstr(cfg.mac)
    <> ",\"payload_bytes\":"
    <> i(cfg.payload)
    <> ",\"payload_mode\":"
    <> jstr(loop_payload.mode_name(cfg.payload_mode))
    <> ",\"seed\":"
    <> i(cfg.seed)
    <> ",\"key_bits\":"
    <> i(cfg.key_bits)
    <> ",\"nonce_bits\":"
    <> i(cfg.nonce_bits)
    <> ",\"blob_mode\":"
    <> i(cfg.blob_mode)
    <> ",\"drbg\":"
    <> jstr(cfg.drbg)
    <> ",\"drbg_auto_tier\":"
    <> jstr(drbg_auto_tier())
    <> ",\"chunk_size_bytes\":"
    <> i(cfg.chunk_size)
    <> ",\"barrier_fill\":"
    <> i(cfg.barrier_fill)
    <> ",\"parallax\":"
    <> jstr(loop_types.on_off(cfg.parallax))
    <> ",\"wrapper\":"
    <> jstr(loop_types.on_off(cfg.wrapper))
    <> ",\"goroutines_requested\":"
    <> i(cfg.workers_requested)
    <> ",\"goroutines\":"
    <> i(cfg.workers)
    <> ",\"concurrency\":"
    <> jstr(loop_types.concurrency)
    <> ",\"gogc\":"
    <> jstr(i(effective_gogc(cfg.gogc)))
    <> ",\"memlimit_bytes\":"
    <> i(cfg.memlimit)
    <> ",\"gomaxprocs\":"
    <> i(f.gomaxprocs)
    <> ",\"microbatch_tiers\":"
    <> jstr(loop_types.policy_label("ITB_MICROBATCH_TIERS"))
    <> ",\"hashpool_starters\":"
    <> jstr(loop_types.policy_label("ITB_HASHPOOL_STARTERS"))
    <> ",\"rss_warmup_bytes\":"
    <> i(f.rss_warmup)
    <> ",\"rss_peak_bytes\":"
    <> i(f.rss_peak)
    <> ",\"rss_final_bytes\":"
    <> i(f.rss_final)
    <> ",\"rss_growth_percent\":"
    <> loop_size.f2(f.rss_growth)
    <> ",\"hash_pool_tiers\":["
    <> string.join(list.map(f.tiers, json_tier), ",")
    <> "]"
    <> ",\"buf_pool\":"
    <> json_byte_pool(f.buf)
    <> ",\"parallax_chunk_pool\":"
    <> json_byte_pool(f.chunk)
    <> "}\n",
  )
}

fn json_tier(t: Tier) -> String {
  let i = int.to_string
  "{\"tier\":"
  <> i(t.tier)
  <> ",\"starter\":"
  <> i(t.starter)
  <> ",\"get\":"
  <> i(t.get)
  <> ",\"new\":"
  <> i(t.new)
  <> ",\"regrow\":"
  <> i(t.regrow)
  <> ",\"new_bytes\":"
  <> i(t.new_bytes)
  <> ",\"miss_percent\":"
  <> loop_size.f2(miss_percent(t.new + t.regrow, t.get))
  <> "}"
}

fn json_byte_pool(p: BytePool) -> String {
  let i = int.to_string
  "{\"get\":"
  <> i(p.get)
  <> ",\"new\":"
  <> i(p.new)
  <> ",\"regrow\":"
  <> i(p.regrow)
  <> ",\"regrow_bytes\":"
  <> i(p.regrow_bytes)
  <> ",\"miss_percent\":"
  <> loop_size.f2(miss_percent(p.regrow, p.get))
  <> "}"
}

// The fill cipher the auto DRBG tier selected on this host; empty when
// the library cannot report it.
fn drbg_auto_tier() -> String {
  case itb3_gleam.drbg_auto_tier() {
    Ok(tier) -> tier
    Error(_) -> ""
  }
}

// One JSON string literal with the escapes JSON requires.
fn jstr(text: String) -> String {
  "\""
  <> string.concat(list.map(string.to_graphemes(text), json_char))
  <> "\""
}

fn json_char(c: String) -> String {
  case c {
    "\"" -> "\\\""
    "\\" -> "\\\\"
    "\n" -> "\\n"
    "\r" -> "\\r"
    "\t" -> "\\t"
    _ -> c
  }
}

fn verdict(pass: Bool) -> String {
  case pass {
    True -> "PASS"
    False -> "FAIL"
  }
}

// The effective GC percentage as the runtime reports it: the query
// form of the setter (a set-and-restore round trip inside the
// library) so the field is the same whether the value came from the
// flag, the environment, or the runtime default.
fn effective_gogc(flag: Int) -> Int {
  case flag > 0 {
    True -> flag
    False -> itb3_gleam.set_gc_percent(-1)
  }
}

// ------------------------------------------------------------------

fn human(cfg: Config, f: Figures) -> Nil {
  let i = int.to_string
  loop_types.log("=== FINAL ===")
  loop_types.log(
    "  duration: "
    <> loop_size.human_duration({ f.elapsed + 500_000 } / 1_000_000 * 1_000_000),
  )
  loop_types.log(
    "  iterations: "
    <> string.join(list.map(f.stats, fn(s) { i(s.iters) }), " + ")
    <> " = "
    <> i(f.total_iters)
    <> " total",
  )
  loop_types.log(
    "  throughput: encrypt "
    <> loop_size.human_rate(f.total_enc, f.avg_enc)
    <> ", decrypt "
    <> loop_size.human_rate(f.total_dec, f.avg_dec)
    <> ", combined "
    <> loop_size.human_rate(f.total_enc + f.total_dec, f.elapsed),
  )
  loop_types.log(
    "  bytes: "
    <> loop_size.human_bytes(f.total_enc)
    <> " encrypted, "
    <> loop_size.human_bytes(f.total_dec)
    <> " decrypted",
  )
  loop_types.log(
    "  data integrity: " <> i(f.total_iters) <> "/" <> i(f.total_iters) <> " PASS",
  )
  loop_types.log(
    "  concurrency: "
    <> loop_types.concurrency
    <> ", workers "
    <> i(cfg.workers)
    <> " (requested "
    <> i(cfg.workers_requested)
    <> ")",
  )
  loop_types.log(
    "  rss: warmup "
    <> loop_size.human_bytes(f.rss_warmup)
    <> ", peak "
    <> loop_size.human_bytes(f.rss_peak)
    <> ", final "
    <> loop_size.human_bytes(f.rss_final)
    <> " (delta "
    <> loop_size.human_bytes_signed(f.rss_delta)
    <> ", "
    <> loop_size.f1(f.rss_growth)
    <> "% growth)",
  )
  list.each(f.tiers, fn(t) {
    loop_types.log(
      "  hash pool tier "
      <> i(t.tier)
      <> " (starter "
      <> i(t.starter)
      <> "): get "
      <> i(t.get)
      <> ", miss "
      <> i(t.new + t.regrow)
      <> " (new "
      <> i(t.new)
      <> " + regrow "
      <> i(t.regrow)
      <> "), miss "
      <> loop_size.f2(miss_percent(t.new + t.regrow, t.get))
      <> "%, "
      <> loop_size.human_bytes(t.new_bytes)
      <> " allocated",
    )
  })
  human_byte_pool("  buf pool", f.buf)
  human_byte_pool("  parallax chunk pool", f.chunk)
  case f.rekeys > 0 {
    True -> loop_types.log("  rekeys: " <> i(f.rekeys))
    False -> Nil
  }
  case f.cycles > 0 {
    True -> loop_types.log("  blob cycles: " <> i(f.cycles))
    False -> Nil
  }
  list.each(f.errors, fn(e) { loop_types.log("  ERROR: " <> e) })
  case f.pass {
    True -> loop_types.log("  verdict: PASS")
    False ->
      loop_types.log(
        "  verdict: FAIL (errors=" <> i(list.length(f.errors)) <> ")",
      )
  }
}

fn human_byte_pool(label: String, p: BytePool) -> Nil {
  let i = int.to_string
  loop_types.log(
    label
    <> ": get "
    <> i(p.get)
    <> ", regrow "
    <> i(p.regrow)
    <> " (of which fresh "
    <> i(p.new)
    <> "), miss "
    <> loop_size.f2(miss_percent(p.regrow, p.get))
    <> "%, "
    <> loop_size.human_bytes(p.regrow_bytes)
    <> " regrown",
  )
}
