# ITB Gleam Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB Erlang binding's Triple Pipeline surface
(`bindings/erlang`) via **native BEAM bytecode interop** — the Gleam
layer calls the Erlang `itb` module directly (through a small
shape-normalising FFI adapter) and adds no FFI hop of its own. The
only native code in the stack is the Erlang binding's NIF shim; the
Erlang application is discovered on the code path at runtime, since
rebar3 applications are not Gleam packages and cannot appear in
`gleam.toml`. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for
validation; the binding carries no ITB construction logic. The
public surface is `itb_gleam` (version, the profile catalogue
`inspect` / `register` / `lookup` / `profiles`, Go runtime knobs),
`itb/pipeline` (`new` / `load` / `load_f` / `save` /
`save_f` / `rekey` / `max_workers` / `free`, Single Message encrypt
/ decrypt), and
`itb/stream` (incremental sessions with `write` / `finish` /
`read`). Handles are opaque NIF resources; the cipher entries run
on dirty CPU schedulers so multi-megabyte calls never stall the
regular BEAM schedulers. The top-level module is named `itb_gleam`
rather than `itb` because the BEAM module name `itb` belongs to the
Erlang backend this binding proxies.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3 gleam
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, rebar3, and Gleam 1.11+. macOS: the same via Homebrew; libitb
builds as `libitb.dylib`.

## Build the shared library

The convenience driver builds `libitb.so`, the C binding's static
archive, the Erlang backend (NIF shim included), and the Gleam
project in one step:

```bash
./bindings/gleam/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a
cd bindings/erlang && rebar3 compile
cd ../gleam && gleam build
```

## Add to a Gleam project

The Erlang backend cannot be a `gleam.toml` dependency (it is a
rebar3 application, not a Gleam package), so consumption is by
source checkout: depend on this project as a path dependency and
keep the built Erlang backend reachable. At the first libitb call
the FFI adapter looks the OTP application `itb` up on the code path
and, when absent, adds its ebin directory from the
`ITB_ERLANG_EBIN` environment variable (when set) or from the
sibling checkout at `../erlang/_build/default/lib/itb/ebin`
relative to this project. The compiled NIF
(`bindings/erlang/priv/itb_nif.so`) resolves `libitb.so` through
its embedded RPATH into the repo `dist/` directory, so no
`LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```gleam
import itb/pipeline

pub fn round_trip() {
  let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
  let assert Ok(blob) = pipeline.save(sender)
  let assert Ok(receiver) = pipeline.load(blob)

  let assert Ok(wire) =
    pipeline.encrypt_message(sender, <<"any text or binary data":utf8>>)
  let assert Ok(plain) = pipeline.decrypt_message(receiver, wire)

  pipeline.free(receiver)
  pipeline.free(sender)
  plain
}

// File-backed equivalent (persist across processes):
// let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", [])
// let assert Ok(Nil) = pipeline.save_f(sender, "session.blob")
// let assert Ok(receiver) = pipeline.load_f("session.blob")
```

Opts override the profile default at `pipeline.new` (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
worker cap) as a list of `#(String, String)` pairs. The resolved
shape is written into the blob, so the receiver loads it with no
opts of its own:

```gleam
let opts = [#("chunkSize", "65536"), #("withWrapper", "false")]
let assert Ok(sender) = pipeline.new("singlemsg-triple-mac-v1", opts)
let assert Ok(blob) = pipeline.save(sender)
let assert Ok(receiver) = pipeline.load(blob)
```

`pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up the
new masters through a fresh `pipeline.load`:

```gleam
let perm = <<0x11:size(256)>>
let wrap = <<0x22:size(256)>>
let assert Ok(blob2) = pipeline.rekey(sender, perm, wrap)
let assert Ok(receiver2) = pipeline.load(blob2)
```

### Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```gleam
let assert Ok(blob) = pipeline.save(sender)             // current blob (BitArray)
let assert Ok(Nil) = pipeline.save_f(sender, "session.blob") // written by libitb, mode 0600
let assert Ok(receiver) = pipeline.load(blob)            // reopen from bytes
let assert Ok(receiver) = pipeline.load_f("session.blob") // reopen from file
let assert Ok(receiver) = pipeline.load_with_masters(blob, perm, wrap) // override the masters
let assert Ok(record) = itb_gleam.inspect(blob)          // profile record, no Pipeline
```

`itb_gleam.inspect` returns the record as JSON text (keys `name`,
`mode`, `width`, `hash`, `hashes`, `keybits`, `mac`, `tagstub`,
`chunk`, `wrapper`, `outer`, `parallax`, `palette`, `segment`;
absent keys are optional fields at their zero value) — the Gleam
stdlib carries no JSON codec, so the text is handed over verbatim
for the caller's own decoder (e.g. `gleam_json`).

The shipped `itb3` command-line utility (see `cmd/itb3`) generates
session blobs on disk (JSON files) that this binding reopens through
`pipeline.load_f`, and also encrypts / decrypts files or stdio
streams from the shell. It is the openssl-style entry point for ITB;
the binding is the programmatic entry point.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `pipeline.load` such a blob
through this binding returns
`Error(ItbError("recipe_primitive_unknown", _))`.

### Profile registry

```gleam
itb_gleam.profiles()                          // sorted List(String)
itb_gleam.lookup("singlemsg-triple-mac-v1")   // Ok(json); unknown -> "unknown_profile"
let assert Ok(Nil) =
  itb_gleam.register(
    "my-profile",
    "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
      <> "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
      <> "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
      <> "\"keybits\":1024,\"parallax\":false,\"wrapper\":false}",
  )
let assert Ok(sender) = pipeline.new("my-profile", [])
```

`itb_gleam.register` takes the same JSON record shape `inspect` /
`lookup` return; a `name` key inside it, if present, must be empty
or equal to the name argument. Every rule — name pattern, reserved
prefixes, field constraints, primitive names — is enforced by
libitb; a duplicate name returns `Error(ItbError("profile_exists", _))`.

### Runtime tuning

`pipeline.max_workers(pipe, n)` sets the worker cap on a live
Pipeline (`n <= 0` selects auto, values above 256 are clamped). The
cap is per-machine tuning and is never written to the blob, so the
receiver may pick its own worker cap after `pipeline.load`. The
`maxWorkers` opts key sets the same cap at `pipeline.new`.

### One-shot streams

`pipeline.encrypt_stream_one_shot` /
`pipeline.decrypt_stream_one_shot` put a whole in-memory payload
through the stream chain in a single call:

```gleam
let assert Ok(wire) = pipeline.encrypt_stream_one_shot(sender, plain)
let assert Ok(back) = pipeline.decrypt_stream_one_shot(receiver, wire)
```

### Incremental stream sessions

For chunked payloads, the session surface mirrors the Erlang
binding (`stream.finish` signals end-of-input; drain with
`stream.read` until the finished flag is `True`):

```gleam
import itb/stream

let assert Ok(session) = stream.encrypt(sender)
let assert Ok(Nil) = stream.write(session, chunk1)
let assert Ok(Nil) = stream.write(session, chunk2)
let assert Ok(Nil) = stream.finish(session)
// Drain until Ok(#(_, True)):
let assert Ok(#(wire_piece, finished)) = stream.read(session, 1_048_576)
stream.free(session)
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`Error(ItbError(status, detail))` — `status` the C binding's status
table entry as a string (e.g. `"mac_failure"`, `"bad_input"`,
`"profile_exists"`), `detail` the Go-side diagnostic. Opts are a
list of string pairs (`[#("keyBits", "1024"), #("nonceBits",
"512")]`) rendered into the URL-query string libitb consumes.

Handle lifetime is garbage-collected: dropping every reference
releases the Go-side state through the NIF resource destructor, and
`pipeline.free` / `stream.free` release eagerly (both idempotent).
A stream `Session` value holds its parent `Pipeline`, and the NIF
resource additionally pins the parent internally, so the pipeline
is never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```gleam
itb_gleam.set_memory_limit(536_870_912) // 512 MiB soft cap
itb_gleam.set_gc_percent(20)            // aggressive GC
```

## Testing

```bash
./bindings/gleam/run_tests.sh
```

The harness builds `libitb.so` + the C archive + the Erlang backend
+ the Gleam project, then invokes `gleam test` (gleeunit). The
suite covers the version string, Single Message round trips (MAC
Authenticated and No MAC profiles, empty through CSPRNG-filled
payloads), an incremental stream round trip on the Non-AEAD
streaming profile, save / load persistence (in memory and through a
file), the profile catalogue, the worker cap, opts pass-through, and
error mapping (unknown profile, unknown opts key, malformed blob,
tampered wire, freed handles) — surface parity checks; the deep
suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/gleam/run_bench.sh
```

Micro-benches: `message` (encrypt_message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench main applies the same caps
programmatically; the shape env vars (`ITB_PROFILE`,
`ITB_INNER_HASH`, `ITB_KEY_BITS`, `ITB_NONCE_BITS`,
`ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`, `ITB_BENCH_MIN_SEC`)
override the BENCH.md defaults. `./run_bench.sh message` /
`./run_bench.sh stream` runs one shape. The bench source lives in
`bench/itb_bench.gleam` with a symlink in `dev/` so the Gleam build
tool compiles it as a dev-profile module.

## eitb utility

An executable launcher under `bindings/gleam/eitb/` mirrors the
shipped Go `tools/eitb` scope for shell smoke tests (build the
binding first; the module source lives in `eitb/itb_eitb.gleam`
with a symlink in `dev/`):

```bash
cd bindings/gleam
./eitb/eitb version
./eitb/eitb profiles
./eitb/eitb inspect <blob-hex>
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `detail` text in an error comes from a process-global
  last-write-wins store on the Go side; under concurrent use it may
  belong to a different call. The status is always attributable.
- `pipeline.rekey` must not run concurrently with cipher calls or
  open stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `pipeline.free` /
  `stream.free` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference
  and let the resource destructor release.
- After `stream.finish`, an empty-spool `stream.read` blocks (on a
  dirty scheduler) until the terminal bytes arrive or the session
  errors; the regular schedulers are unaffected.
- The Erlang backend joins the code path at the first libitb call,
  not at compile time; a missing or unbuilt backend surfaces as a
  runtime `itb_backend_not_found` crash naming the path probed (set
  `ITB_ERLANG_EBIN` to relocate it).
