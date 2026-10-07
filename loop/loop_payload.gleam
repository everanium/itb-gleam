//// Plaintext content: the payload modes, the seeded per-worker
//// generator, and the buffer fill from the operating-system CSPRNG.
////
//// The modes the --payload-mode flag selects:
////
////   - Fixed: one CSPRNG-generated buffer per worker, held unchanged
////     for the whole run (the default).
////   - Rotating: the buffer is regenerated before every iteration, so
////     no two encrypt calls see the same plaintext.
////   - PatternZero / PatternFf: degenerate constant fills (all 0x00 /
////     all 0xFF) probing minimum-entropy plaintext handling.
////   - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
////     structured text.

import gleam/bit_array
import gleam/int
import gleam/list
import loop_ffi
import loop_types.{
  type PayloadMode, Fixed, PatternAscii, PatternFf, PatternZero, Rotating,
}

const mask64 = 0xFFFFFFFFFFFFFFFF

pub fn mode_name(mode: PayloadMode) -> String {
  case mode {
    Fixed -> "fixed"
    Rotating -> "rotating"
    PatternZero -> "pattern-zero"
    PatternFf -> "pattern-ff"
    PatternAscii -> "pattern-ascii"
  }
}

pub fn parse_mode(text: String) -> Result(PayloadMode, Nil) {
  case text {
    "fixed" -> Ok(Fixed)
    "rotating" -> Ok(Rotating)
    "pattern-zero" -> Ok(PatternZero)
    "pattern-ff" -> Ok(PatternFf)
    "pattern-ascii" -> Ok(PatternAscii)
    _ -> Error(Nil)
  }
}

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
pub fn seed_worker(seed: Int, worker_id: Int) -> Int {
  int.bitwise_and(seed + worker_id + 1, mask64)
}

fn splitmix64(state0: Int) -> #(Int, Int) {
  let s = int.bitwise_and(state0 + 0x9E3779B97F4A7C15, mask64)
  let z1 =
    int.bitwise_and(
      int.bitwise_exclusive_or(s, int.bitwise_shift_right(s, 30))
        * 0xBF58476D1CE4E5B9,
      mask64,
    )
  let z2 =
    int.bitwise_and(
      int.bitwise_exclusive_or(z1, int.bitwise_shift_right(z1, 27))
        * 0x94D049BB133111EB,
      mask64,
    )
  #(int.bitwise_exclusive_or(z2, int.bitwise_shift_right(z2, 31)), s)
}

/// Draws `n` bytes from the operating-system CSPRNG.
pub fn random_bytes(n: Int) -> BitArray {
  loop_ffi.random_bytes(n)
}

/// Builds one plaintext buffer according to the payload mode. The
/// fixed and rotating modes draw from the seeded generator when the
/// run is seeded and from the OS CSPRNG otherwise; the pattern modes
/// are deterministic regardless of the seed. Returns the buffer and
/// the generator state to carry into the next fill.
pub fn fill(
  mode: PayloadMode,
  seeded: Bool,
  rng: Int,
  n: Int,
) -> #(BitArray, Int) {
  case mode, seeded {
    Fixed, False -> #(random_bytes(n), rng)
    Rotating, False -> #(random_bytes(n), rng)
    Fixed, True -> seeded_fill(rng, n, [])
    Rotating, True -> seeded_fill(rng, n, [])
    PatternZero, _ -> #(repeat_byte(<<0>>, n), rng)
    PatternFf, _ -> #(repeat_byte(<<0xFF>>, n), rng)
    PatternAscii, _ -> #(ascii_ramp(n), rng)
  }
}

// Eight little-endian bytes per generator draw, the last draw
// truncated to the bytes the buffer still wants.
fn seeded_fill(rng: Int, n: Int, acc: List(BitArray)) -> #(BitArray, Int) {
  case n <= 0 {
    True -> #(bit_array.concat(list.reverse(acc)), rng)
    False -> {
      let #(v, rng1) = splitmix64(rng)
      let word = <<v:size(64)-little>>
      case n >= 8 {
        True -> seeded_fill(rng1, n - 8, [word, ..acc])
        False ->
          case bit_array.slice(word, 0, n) {
            Ok(head) -> seeded_fill(rng1, 0, [head, ..acc])
            Error(Nil) -> seeded_fill(rng1, 0, acc)
          }
      }
    }
  }
}

// A one-byte period repeated, doubling the accumulator rather than
// appending byte by byte so a large buffer costs log(n) copies.
fn repeat_byte(byte: BitArray, n: Int) -> BitArray {
  case n <= 0 {
    True -> <<>>
    False -> grow(byte, n)
  }
}

fn grow(acc: BitArray, want: Int) -> BitArray {
  let have = bit_array.byte_size(acc)
  case have >= want {
    True ->
      case bit_array.slice(acc, 0, want) {
        Ok(cut) -> cut
        Error(Nil) -> acc
      }
    False ->
      case have * 2 <= want {
        True -> grow(bit_array.append(acc, acc), want)
        False ->
          case bit_array.slice(acc, 0, want - have) {
            Ok(tail) -> bit_array.append(acc, tail)
            Error(Nil) -> acc
          }
      }
  }
}

// Byte i is 'A' + i % 26, built from one 26-byte period so a large
// buffer costs a copy rather than a per-byte comprehension.
fn ascii_ramp(n: Int) -> BitArray {
  let period = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZ":utf8>>
  case n <= 0 {
    True -> <<>>
    False -> grow(period, n)
  }
}
