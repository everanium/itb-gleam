//// Size and duration parsing, the monotonic clock, and the human
//// renderings of sizes, rates and durations. Every rendering here is
//// part of the output contract shared with the Go harness and the
//// other bindings' loop utilities, so the formats are fixed to the
//// character, not to taste.

import gleam/float
import gleam/int
import gleam/list
import gleam/string
import loop_ffi

const suffixes = [
  #("KIB", 1024), #("KB", 1024), #("K", 1024), #("MIB", 1_048_576),
  #("MB", 1_048_576), #("M", 1_048_576), #("GIB", 1_073_741_824),
  #("GB", 1_073_741_824), #("G", 1_073_741_824), #("B", 1),
]

const units = [
  #("ns", 1.0), #("us", 1000.0), #("ms", 1_000_000.0), #("s", 1_000_000_000.0),
  #("m", 60_000_000_000.0), #("h", 3_600_000_000_000.0),
]

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary
/// multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B
/// or none = bytes; matching is case-insensitive and surrounding
/// whitespace is trimmed.
pub fn parse_size(text: String) -> Result(Int, Nil) {
  let upper = string.uppercase(string.trim(text))
  case upper {
    "" -> Error(Nil)
    _ -> {
      let #(digits, mult) = split_suffix(upper)
      // Whitespace may sit between the number and its unit.
      case string.trim_end(digits) {
        "" -> Error(Nil)
        trimmed ->
          case all_digits(trimmed) {
            False -> Error(Nil)
            True ->
              case int.parse(trimmed) {
                Ok(n) -> Ok(n * mult)
                Error(Nil) -> Error(Nil)
              }
          }
      }
    }
  }
}

fn all_digits(text: String) -> Bool {
  list.all(string.to_graphemes(text), fn(c) {
    c == "0" || c == "1" || c == "2" || c == "3" || c == "4" || c == "5"
    || c == "6" || c == "7" || c == "8" || c == "9"
  })
}

fn split_suffix(upper: String) -> #(String, Int) {
  case
    list.find(suffixes, fn(entry) { string.ends_with(upper, entry.0) })
  {
    Ok(#(suffix, mult)) -> #(
      string.slice(upper, 0, string.length(upper) - string.length(suffix)),
      mult,
    )
    Error(Nil) -> #(upper, 1)
  }
}

/// Parses the Go duration grammar — a sequence of decimal numbers
/// each followed by a unit (h, m, s, ms, us, ns), such as "30s",
/// "5m", "1h30m", "1.5s" — into nanoseconds.
pub fn parse_duration(text: String) -> Result(Int, Nil) {
  case text {
    "" -> Error(Nil)
    _ -> duration_parts(text, 0.0)
  }
}

fn duration_parts(text: String, total: Float) -> Result(Int, Nil) {
  case text {
    "" ->
      case total <=. 9.2e18 {
        True -> Ok(float.truncate(total))
        False -> Error(Nil)
      }
    _ ->
      case number_prefix(text) {
        Error(Nil) -> Error(Nil)
        Ok(#(value, rest)) ->
          case unit_prefix(rest, units) {
            Error(Nil) -> Error(Nil)
            Ok(#(mult, rest2)) ->
              duration_parts(rest2, total +. value *. mult)
          }
      }
  }
}

// A decimal run with an optional fraction. A leading sign is not part
// of the grammar.
fn number_prefix(text: String) -> Result(#(Float, String), Nil) {
  let digits = take_number(text, "")
  case digits {
    "" -> Error(Nil)
    _ -> {
      let rest = string.drop_start(text, string.length(digits))
      case float.parse(digits) {
        Ok(v) -> Ok(#(v, rest))
        Error(Nil) ->
          case int.parse(digits) {
            Ok(n) -> Ok(#(int.to_float(n), rest))
            Error(Nil) -> Error(Nil)
          }
      }
    }
  }
}

fn take_number(text: String, acc: String) -> String {
  case string.pop_grapheme(text) {
    Error(Nil) -> acc
    Ok(#(c, rest)) ->
      case is_digit_or_dot(c) {
        True -> take_number(rest, acc <> c)
        False -> acc
      }
  }
}

fn is_digit_or_dot(c: String) -> Bool {
  c == "." || all_digits(c)
}

fn unit_prefix(
  text: String,
  candidates: List(#(String, Float)),
) -> Result(#(Float, String), Nil) {
  case candidates {
    [] -> Error(Nil)
    [#(unit, mult), ..rest] ->
      case string.starts_with(text, unit) {
        False -> unit_prefix(text, rest)
        True -> {
          let tail = string.drop_start(text, string.length(unit))
          // A longer word starting with this unit is not this unit.
          case starts_with_letter(tail) {
            True -> unit_prefix(text, rest)
            False -> Ok(#(mult, tail))
          }
        }
      }
  }
}

fn starts_with_letter(text: String) -> Bool {
  case string.pop_grapheme(text) {
    Error(Nil) -> False
    Ok(#(c, _)) -> string.lowercase(c) != string.uppercase(c)
  }
}

/// Monotonic wall clock in nanoseconds.
pub fn now_ns() -> Int {
  loop_ffi.monotonic_ns()
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
pub fn human_bytes(n: Int) -> String {
  case n {
    _ if n >= 1_073_741_824 ->
      f1(int.to_float(n) /. 1_073_741_824.0) <> "GiB"
    _ if n >= 1_048_576 -> f1(int.to_float(n) /. 1_048_576.0) <> "MiB"
    _ if n >= 1024 -> f1(int.to_float(n) /. 1024.0) <> "KiB"
    _ -> int.to_string(n) <> "B"
  }
}

/// Renders a possibly-negative byte delta with an explicit sign.
pub fn human_bytes_signed(n: Int) -> String {
  case n < 0 {
    True -> "-" <> human_bytes(-n)
    False -> "+" <> human_bytes(n)
  }
}

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
pub fn mb_per_sec(bytes: Int, ns: Int) -> Float {
  case ns <= 0 {
    True -> 0.0
    False ->
      int.to_float(bytes) /. 1_048_576.0 /. { int.to_float(ns) /. 1.0e9 }
  }
}

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
pub fn human_rate(bytes: Int, ns: Int) -> String {
  case ns <= 0 {
    True -> "n/a"
    False -> f1(mb_per_sec(bytes, ns)) <> "MB/s"
  }
}

/// Renders a duration the way Go's time.Duration prints: below one
/// second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
/// where the hour part appears when non-zero, the minute part when
/// the hour part appears or the minutes are non-zero, and the seconds
/// carry their fraction with trailing zeros removed ("5s", "5.003s",
/// "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
pub fn human_duration(ns0: Int) -> String {
  let ns = int.absolute_value(ns0)
  case ns {
    0 -> "0s"
    _ if ns < 1_000_000_000 ->
      // The remainder is scaled to nine digits so the fraction
      // renderer is the same one the seconds branch uses.
      int.to_string(ns / 1_000_000)
      <> fraction({ ns % 1_000_000 } * 1000)
      <> "ms"
    _ -> {
      let hours = ns / 3_600_000_000_000
      let rem1 = ns % 3_600_000_000_000
      let minutes = rem1 / 60_000_000_000
      let rem2 = rem1 % 60_000_000_000
      let seconds = rem2 / 1_000_000_000
      let frac = rem2 % 1_000_000_000
      let hpart = case hours > 0 {
        True -> int.to_string(hours) <> "h"
        False -> ""
      }
      let mpart = case hours > 0 || minutes > 0 {
        True -> int.to_string(minutes) <> "m"
        False -> ""
      }
      hpart <> mpart <> int.to_string(seconds) <> fraction(frac) <> "s"
    }
  }
}

// The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
// with trailing zeros removed; empty for zero.
fn fraction(frac_ns: Int) -> String {
  case frac_ns {
    0 -> ""
    _ -> {
      let padded = string.pad_start(int.to_string(frac_ns), 9, "0")
      case trim_zeros(padded) {
        "" -> ""
        trimmed -> "." <> trimmed
      }
    }
  }
}

fn trim_zeros(text: String) -> String {
  case string.ends_with(text, "0") {
    True -> trim_zeros(string.slice(text, 0, string.length(text) - 1))
    False -> text
  }
}

/// A float with one decimal, never in exponent form.
pub fn f1(v: Float) -> String {
  loop_ffi.format_float(v, 1)
}

/// A float with two decimals, never in exponent form.
pub fn f2(v: Float) -> String {
  loop_ffi.format_float(v, 2)
}

/// A float with three decimals, never in exponent form.
pub fn f3(v: Float) -> String {
  loop_ffi.format_float(v, 3)
}
