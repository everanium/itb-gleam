//// itb_eitb — command-line demonstrator for the ITB Gleam binding.
////
//// Subcommands:
////
////   eitb version                                   library + binding versions
////   eitb hashes                                    shipped hash primitive roster
////   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
////   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
////
//// `encrypt` prints the session blob to stderr as hex; feed that
//// hex back to `decrypt` on the receiving side.
////
//// The source lives in eitb/ with a symlink in dev/ so the build
//// tool picks it up as a dev-profile module; the eitb/eitb bash
//// launcher invokes it via `gleam run -m itb_eitb -- <args>`.

import gleam/int
import gleam/io
import gleam/list
import gleam/string
import itb/pipeline.{type Pipeline}
import itb/stream
import itb_gleam.{type ItbError, ItbError}

const eitb_gleam_version = "0.3.3"

@external(erlang, "itb_gleam_ffi", "argv")
fn argv() -> List(String)

@external(erlang, "itb_gleam_ffi", "read_file")
fn read_file(path: String) -> Result(BitArray, String)

@external(erlang, "itb_gleam_ffi", "write_file")
fn write_file(path: String, data: BitArray) -> Result(Nil, String)

@external(erlang, "itb_gleam_ffi", "hex_encode")
fn hex_encode(data: BitArray) -> String

@external(erlang, "itb_gleam_ffi", "hex_decode")
fn hex_decode(hex: String) -> Result(BitArray, Nil)

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> a

@external(erlang, "erlang", "byte_size")
fn byte_size(data: BitArray) -> Int

// Erlang's filelib:ensure_dir/1 creates every directory component of
// the passed path except the final one — call with the file path and
// the parent directories are created recursively.
@external(erlang, "filelib", "ensure_dir")
fn filelib_ensure_dir(path: String) -> Result(Nil, a)

// Profiles whose canonical name begins with "streaming-" route
// through the streaming session pair instead of the Single Message
// pair.
fn is_streaming_profile(profile: String) -> Bool {
  string.starts_with(profile, "streaming-")
}

fn ensure_parent_dir(path: String) -> Nil {
  let _ = filelib_ensure_dir(path)
  Nil
}

// One-shot streaming through the encrypt/decrypt session pair: open
// the session, feed the whole payload, signal end, and drain until
// finished.
fn stream_one_shot(
  pipe: Pipeline,
  direction: StreamDirection,
  payload: BitArray,
) -> Result(BitArray, ItbError) {
  let begin_fn = case direction {
    StreamEncrypt -> stream.encrypt
    StreamDecrypt -> stream.decrypt
  }
  case begin_fn(pipe) {
    Error(e) -> Error(e)
    Ok(session) -> {
      let result = feed_and_drain(session, payload)
      stream.free(session)
      result
    }
  }
}

type StreamDirection {
  StreamEncrypt
  StreamDecrypt
}

fn feed_and_drain(
  session: stream.Session,
  payload: BitArray,
) -> Result(BitArray, ItbError) {
  case stream.write(session, payload) {
    Error(e) -> Error(e)
    Ok(Nil) ->
      case stream.finish(session) {
        Error(e) -> Error(e)
        Ok(Nil) -> drain_stream(session, <<>>)
      }
  }
}

fn drain_stream(
  session: stream.Session,
  acc: BitArray,
) -> Result(BitArray, ItbError) {
  case stream.read(session, 1_048_576) {
    Error(e) -> Error(e)
    Ok(#(piece, True)) -> Ok(<<acc:bits, piece:bits>>)
    Ok(#(piece, False)) -> drain_stream(session, <<acc:bits, piece:bits>>)
  }
}

pub fn main() {
  halt(dispatch(argv()))
}

fn dispatch(args: List(String)) -> Int {
  case args {
    ["version"] -> cmd_version()
    ["hashes"] -> cmd_hashes()
    ["encrypt", profile, in_file, out_file] ->
      cmd_encrypt(profile, in_file, out_file)
    ["decrypt", profile, blob_hex, in_file, out_file] ->
      cmd_decrypt(profile, blob_hex, in_file, out_file)
    _ -> usage()
  }
}

fn usage() -> Int {
  io.println_error(
    "usage: eitb version\n"
    <> "       eitb hashes\n"
    <> "       eitb encrypt <profile> <in-file> <out-file>\n"
    <> "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>",
  )
  2
}

fn fail(what: String, error: ItbError) -> Int {
  let ItbError(status, detail) = error
  io.println_error("eitb: " <> what <> ": " <> status <> ": " <> detail)
  1
}

// Defensive Go-runtime pacing for cipher workloads on large files:
// a soft memory cap + aggressive GC keep the scratch heap bounded.
// The setter return values report the previous settings, not an
// error.
fn cap_go_runtime() -> Nil {
  let _ = itb_gleam.set_memory_limit(536_870_912)
  let _ = itb_gleam.set_gc_percent(20)
  Nil
}

fn cmd_version() -> Int {
  case itb_gleam.version() {
    Ok(version) -> {
      io.println("libitb " <> version)
      io.println("itb-gleam " <> eitb_gleam_version)
      0
    }
    Error(error) -> fail("version", error)
  }
}

fn cmd_hashes() -> Int {
  itb_gleam.hashes()
  |> list.index_map(fn(hash, index) {
    let #(name, width) = hash
    io.println(
      string.pad_start(int.to_string(index), 2, " ")
      <> "  "
      <> string.pad_end(name, 12, " ")
      <> " "
      <> int.to_string(width)
      <> " bits",
    )
  })
  0
}

fn cmd_encrypt(profile: String, in_file: String, out_file: String) -> Int {
  cap_go_runtime()
  case read_file(in_file) {
    Error(read_err) -> {
      io.println_error("eitb: cannot read " <> in_file <> ": " <> read_err)
      1
    }
    Ok(plain) ->
      case pipeline.new(profile, []) {
        Error(error) -> fail("init", error)
        Ok(pipe) -> {
          let rc = encrypt_with(pipe, plain, profile, in_file, out_file)
          pipeline.free(pipe)
          rc
        }
      }
  }
}

fn encrypt_with(
  pipe: Pipeline,
  plain: BitArray,
  profile: String,
  in_file: String,
  out_file: String,
) -> Int {
  let result = case is_streaming_profile(profile) {
    True -> stream_one_shot(pipe, StreamEncrypt, plain)
    False -> pipeline.encrypt_message(pipe, plain)
  }
  case result {
    Error(error) -> fail("encrypt", error)
    Ok(wire) -> {
      ensure_parent_dir(out_file)
      case write_file(out_file, wire) {
        Error(write_err) -> {
          io.println_error(
            "eitb: cannot write " <> out_file <> ": " <> write_err,
          )
          1
        }
        Ok(Nil) -> {
          let assert Ok(blob) = pipeline.blob(pipe)
          io.println_error(hex_encode(blob))
          io.println(
            "encrypted "
            <> in_file
            <> " -> "
            <> out_file
            <> " ("
            <> int.to_string(byte_size(plain))
            <> " -> "
            <> int.to_string(byte_size(wire))
            <> " bytes)",
          )
          0
        }
      }
    }
  }
}

fn cmd_decrypt(
  profile: String,
  blob_hex: String,
  in_file: String,
  out_file: String,
) -> Int {
  cap_go_runtime()
  case hex_decode(blob_hex) {
    Error(Nil) -> {
      io.println_error("eitb: invalid blob hex")
      1
    }
    Ok(blob) ->
      case read_file(in_file) {
        Error(read_err) -> {
          io.println_error("eitb: cannot read " <> in_file <> ": " <> read_err)
          1
        }
        Ok(wire) -> decrypt_with(profile, blob, wire, in_file, out_file)
      }
  }
}

fn decrypt_with(
  profile: String,
  blob: BitArray,
  wire: BitArray,
  in_file: String,
  out_file: String,
) -> Int {
  case pipeline.open(profile, blob, []) {
    Error(error) -> fail("open", error)
    Ok(pipe) -> {
      let result = case is_streaming_profile(profile) {
        True -> stream_one_shot(pipe, StreamDecrypt, wire)
        False -> pipeline.decrypt_message(pipe, wire)
      }
      let rc = case result {
        Error(error) -> fail("decrypt", error)
        Ok(plain) -> {
          ensure_parent_dir(out_file)
          case write_file(out_file, plain) {
            Error(write_err) -> {
              io.println_error(
                "eitb: cannot write " <> out_file <> ": " <> write_err,
              )
              1
            }
            Ok(Nil) -> {
              io.println(
                "decrypted "
                <> in_file
                <> " -> "
                <> out_file
                <> " ("
                <> int.to_string(byte_size(wire))
                <> " -> "
                <> int.to_string(byte_size(plain))
                <> " bytes)",
              )
              0
            }
          }
        }
      }
      pipeline.free(pipe)
      rc
    }
  }
}
