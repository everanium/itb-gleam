%% itb_gleam_ffi — FFI adapter for the ITB Gleam binding.
%%
%% Normalises the Erlang binding's return shapes into the tuple
%% layouts Gleam's type system expects, and lazily puts the Erlang
%% backend (bindings/erlang, OTP application `itb`) on the code path
%% at first use. No ITB construction logic lives here: every call is
%% a pass-through to the `itb` module, whose NIF shim carries the
%% only native code in the BEAM stack.
%%
%% Shape normalisation:
%%   - `ok`                     -> `{ok, nil}`      (Gleam Result(Nil, e))
%%   - `{ok, Data, Finished}`   -> `{ok, {Data, Finished}}`
%%   - `{error, {Status, Det}}` -> `{error, {itb_error, StatusBin, Det}}`
%%     (the three-tuple is the runtime layout of the Gleam
%%     `ItbError(status, detail)` record; Status is rendered as a
%%     binary so Gleam pattern-matches on plain strings)
%%
%% Backend discovery: the OTP application `itb` is looked up on the
%% code path first; when absent, its ebin directory is added from
%% $ITB_ERLANG_EBIN when set, else from the sibling checkout at
%% ../erlang/_build/default/lib/itb/ebin (resolved relative to this
%% module's own beam location, so the lookup is independent of the
%% caller's working directory).

-module(itb_gleam_ffi).

-export([init/2, open/5, blob/1, rekey/3, free/1,
         encrypt_message/2, decrypt_message/2,
         encrypt_stream_one_shot/2, decrypt_stream_one_shot/2,
         encrypt_stream/1, decrypt_stream/1,
         stream_write/2, stream_end/1, stream_read/2, stream_free/1,
         register_profile/2, version/0, hashes/0, last_error/0,
         set_memory_limit/1, set_gc_percent/1,
         env/2, now_us/0, read_file/1, write_file/2,
         hex_encode/1, hex_decode/1, argv/0, flip_byte/2]).

%% ------------------------------------------------------------------
%% Pipeline lifecycle
%% ------------------------------------------------------------------

init(Profile, Opts) ->
    ok = ensure_itb(),
    norm(itb:init(Profile, Opts)).

open(Profile, Blob, Opts, PermMaster, WrapMaster) ->
    ok = ensure_itb(),
    norm(itb:open(Profile, Blob, Opts, PermMaster, WrapMaster)).

blob(Pipeline) ->
    norm(itb:blob(Pipeline)).

rekey(Pipeline, PermMaster, WrapMaster) ->
    norm(itb:rekey(Pipeline, PermMaster, WrapMaster)).

free(Pipeline) ->
    ok = itb:free(Pipeline),
    nil.

%% ------------------------------------------------------------------
%% Single Message encrypt / decrypt
%% ------------------------------------------------------------------

encrypt_message(Pipeline, Plain) ->
    norm(itb:encrypt_message(Pipeline, Plain)).

decrypt_message(Pipeline, Wire) ->
    norm(itb:decrypt_message(Pipeline, Wire)).

%% ------------------------------------------------------------------
%% One-shot stream encrypt / decrypt
%% ------------------------------------------------------------------

encrypt_stream_one_shot(Pipeline, Plain) ->
    norm(itb:encrypt_stream_one_shot(Pipeline, Plain)).

decrypt_stream_one_shot(Pipeline, Wire) ->
    norm(itb:decrypt_stream_one_shot(Pipeline, Wire)).

%% ------------------------------------------------------------------
%% Incremental stream sessions
%% ------------------------------------------------------------------

encrypt_stream(Pipeline) ->
    norm(itb:encrypt_stream(Pipeline)).

decrypt_stream(Pipeline) ->
    norm(itb:decrypt_stream(Pipeline)).

stream_write(Stream, Data) ->
    norm(itb:stream_write(Stream, Data)).

stream_end(Stream) ->
    norm(itb:stream_end(Stream)).

stream_read(Stream, MaxBytes) ->
    case itb:stream_read(Stream, MaxBytes) of
        {ok, Data, Finished} -> {ok, {Data, Finished}};
        {error, Reason} -> {error, err(Reason)}
    end.

stream_free(Stream) ->
    ok = itb:stream_free(Stream),
    nil.

%% ------------------------------------------------------------------
%% Profile registration / runtime / diagnostics
%% ------------------------------------------------------------------

register_profile(Name, Opts) ->
    ok = ensure_itb(),
    norm(itb:register_profile(Name, Opts)).

version() ->
    ok = ensure_itb(),
    norm(itb:version()).

hashes() ->
    ok = ensure_itb(),
    itb:hashes().

last_error() ->
    ok = ensure_itb(),
    itb:last_error().

set_memory_limit(Bytes) ->
    ok = ensure_itb(),
    itb:set_memory_limit(Bytes).

set_gc_percent(Pct) ->
    ok = ensure_itb(),
    itb:set_gc_percent(Pct).

%% ------------------------------------------------------------------
%% Utility helpers for the bench / eitb / test modules
%% ------------------------------------------------------------------

%% Environment lookup with a default; unset and empty both fall back.
env(Name, Default) ->
    case os:getenv(binary_to_list(Name)) of
        false -> Default;
        "" -> Default;
        Value -> unicode:characters_to_binary(Value)
    end.

%% Monotonic wall-clock in microseconds for the bench timing loop.
now_us() ->
    erlang:monotonic_time(microsecond).

read_file(Path) ->
    case file:read_file(Path) of
        {ok, Data} -> {ok, Data};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

write_file(Path, Data) ->
    case file:write_file(Path, Data) of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

hex_encode(Data) ->
    binary:encode_hex(Data, lowercase).

hex_decode(Hex) ->
    try
        {ok, binary:decode_hex(Hex)}
    catch
        _:_ -> {error, nil}
    end.

%% Plain command-line arguments (after `--` under `gleam run`).
argv() ->
    [unicode:characters_to_binary(Arg) || Arg <- init:get_plain_arguments()].

%% XORs one byte of a binary with 0xFF (tamper probe in tests).
flip_byte(Bin, Pos) ->
    <<Before:Pos/binary, Byte, After/binary>> = Bin,
    <<Before/binary, (Byte bxor 16#FF), After/binary>>.

%% ------------------------------------------------------------------
%% Shape normalisation + backend discovery
%% ------------------------------------------------------------------

norm(ok) -> {ok, nil};
norm({ok, Value}) -> {ok, Value};
norm({error, Reason}) -> {error, err(Reason)}.

%% Runtime layout of the Gleam record ItbError(status: String,
%% detail: String) defined in src/itb_gleam.gleam.
err({Status, Detail}) ->
    {itb_error, atom_to_binary(Status, utf8), Detail}.

ensure_itb() ->
    case erlang:module_loaded(itb) of
        true -> ok;
        false -> load_itb()
    end.

load_itb() ->
    case code:ensure_loaded(itb) of
        {module, itb} ->
            ok;
        {error, _} ->
            Ebin = backend_ebin(),
            case code:add_pathz(Ebin) of
                true -> ok;
                {error, bad_directory} ->
                    erlang:error({itb_backend_not_found, Ebin})
            end,
            {module, itb} = code:ensure_loaded(itb),
            ok
    end.

backend_ebin() ->
    case os:getenv("ITB_ERLANG_EBIN") of
        false -> default_backend_ebin();
        "" -> default_backend_ebin();
        Env -> Env
    end.

%% This module's beam lives at
%% <binding>/build/dev/erlang/itb_gleam/ebin/itb_gleam_ffi.beam; the
%% sibling Erlang binding's compiled application sits five levels up
%% and over at ../erlang/_build/default/lib/itb/ebin.
default_backend_ebin() ->
    Here = filename:dirname(code:which(?MODULE)),
    filename:join([Here, "..", "..", "..", "..", "..",
                   "..", "erlang", "_build", "default", "lib", "itb",
                   "ebin"]).
