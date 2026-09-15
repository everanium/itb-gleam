%% itb3_gleam_ffi — FFI adapter for the ITB Gleam binding.
%%
%% Normalises the Erlang binding's return shapes into the tuple
%% layouts Gleam's type system expects, and lazily puts the Erlang
%% backend (bindings/erlang, OTP application `libitb3`) on the code path
%% at first use. No ITB construction logic lives here: every call is
%% a pass-through to the `itb3` module, whose NIF shim carries the
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
%% Backend discovery: the OTP application `libitb3` is looked up on the
%% code path first; when absent, its ebin directory is added from
%% $ITB_ERLANG_EBIN when set, else from the sibling checkout at
%% ../erlang/_build/default/lib/libitb3/ebin (resolved relative to this
%% module's own beam location, so the lookup is independent of the
%% caller's working directory).

-module(itb3_gleam_ffi).

-export([init/2, load/3, load_f/3, save/1, save_f/2, max_workers/2,
         rekey/3, free/1,
         encrypt_message/2, decrypt_message/2,
         encrypt_stream_one_shot/2, decrypt_stream_one_shot/2,
         encrypt_stream/1, decrypt_stream/1,
         stream_write/2, stream_end/1, stream_read/2, stream_free/1,
         inspect/1, register/2, lookup/1, profiles/0,
         version/0, last_error/0,
         set_memory_limit/1, set_gc_percent/1,
         env/2, now_us/0, read_file/1, write_file/2, delete_file/1,
         hex_encode/1, hex_decode/1, argv/0, flip_byte/2]).

%% ------------------------------------------------------------------
%% Pipeline lifecycle
%% ------------------------------------------------------------------

init(Profile, Opts) ->
    ok = ensure_itb(),
    norm(itb3:init(Profile, Opts)).

load(Blob, PermMaster, WrapMaster) ->
    ok = ensure_itb(),
    norm(itb3:load(Blob, PermMaster, WrapMaster)).

load_f(Path, PermMaster, WrapMaster) ->
    ok = ensure_itb(),
    norm(itb3:load_f(Path, PermMaster, WrapMaster)).

save(Pipeline) ->
    norm(itb3:save(Pipeline)).

save_f(Pipeline, Path) ->
    norm(itb3:save_f(Pipeline, Path)).

max_workers(Pipeline, N) ->
    norm(itb3:max_workers(Pipeline, N)).

rekey(Pipeline, PermMaster, WrapMaster) ->
    norm(itb3:rekey(Pipeline, PermMaster, WrapMaster)).

free(Pipeline) ->
    ok = itb3:free(Pipeline),
    nil.

%% ------------------------------------------------------------------
%% Single Message encrypt / decrypt
%% ------------------------------------------------------------------

encrypt_message(Pipeline, Plain) ->
    norm(itb3:encrypt_message(Pipeline, Plain)).

decrypt_message(Pipeline, Wire) ->
    norm(itb3:decrypt_message(Pipeline, Wire)).

%% ------------------------------------------------------------------
%% One-shot stream encrypt / decrypt
%% ------------------------------------------------------------------

encrypt_stream_one_shot(Pipeline, Plain) ->
    norm(itb3:encrypt_stream_one_shot(Pipeline, Plain)).

decrypt_stream_one_shot(Pipeline, Wire) ->
    norm(itb3:decrypt_stream_one_shot(Pipeline, Wire)).

%% ------------------------------------------------------------------
%% Incremental stream sessions
%% ------------------------------------------------------------------

encrypt_stream(Pipeline) ->
    norm(itb3:encrypt_stream(Pipeline)).

decrypt_stream(Pipeline) ->
    norm(itb3:decrypt_stream(Pipeline)).

stream_write(Stream, Data) ->
    norm(itb3:stream_write(Stream, Data)).

stream_end(Stream) ->
    norm(itb3:stream_end(Stream)).

stream_read(Stream, MaxBytes) ->
    case itb3:stream_read(Stream, MaxBytes) of
        {ok, Data, Finished} -> {ok, {Data, Finished}};
        {error, Reason} -> {error, err(Reason)}
    end.

stream_free(Stream) ->
    ok = itb3:stream_free(Stream),
    nil.

%% ------------------------------------------------------------------
%% Profile registration / runtime / diagnostics
%% ------------------------------------------------------------------

%% The profile record crosses as JSON text on the Gleam side (the
%% Gleam stdlib carries no JSON codec); the Erlang backend hands the
%% record over as a map, re-encoded here with the OTP json module.
inspect(Blob) ->
    ok = ensure_itb(),
    json_text(itb3:inspect(Blob)).

register(Name, ProfileJson) ->
    ok = ensure_itb(),
    norm(itb3:register(Name, ProfileJson)).

lookup(Name) ->
    ok = ensure_itb(),
    json_text(itb3:lookup(Name)).

profiles() ->
    ok = ensure_itb(),
    itb3:profiles().

json_text({ok, Record}) -> {ok, iolist_to_binary(json:encode(Record))};
json_text({error, Reason}) -> {error, err(Reason)}.

version() ->
    ok = ensure_itb(),
    norm(itb3:version()).

last_error() ->
    ok = ensure_itb(),
    itb3:last_error().

set_memory_limit(Bytes) ->
    ok = ensure_itb(),
    itb3:set_memory_limit(Bytes).

set_gc_percent(Pct) ->
    ok = ensure_itb(),
    itb3:set_gc_percent(Pct).

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

delete_file(Path) ->
    case file:delete(Path) of
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
%% detail: String) defined in src/itb3_gleam.gleam.
err({Status, Detail}) ->
    {itb_error, atom_to_binary(Status, utf8), Detail}.

ensure_itb() ->
    %% Both backend modules must be reachable: this adapter calls the
    %% `itb3` API module and the `itb3_nif` stub module directly, and
    %% they load independently, so checking only one can leave the other
    %% unresolved when the backend is not already on the code path.
    case erlang:module_loaded(itb3) andalso erlang:module_loaded(itb3_nif) of
        true -> ok;
        false -> load_itb()
    end.

load_itb() ->
    case {code:ensure_loaded(itb3), code:ensure_loaded(itb3_nif)} of
        {{module, itb3}, {module, itb3_nif}} ->
            ok;
        _ ->
            Ebin = backend_ebin(),
            case code:add_pathz(Ebin) of
                true -> ok;
                {error, bad_directory} ->
                    erlang:error({itb_backend_not_found, Ebin})
            end,
            {module, itb3} = code:ensure_loaded(itb3),
            {module, itb3_nif} = code:ensure_loaded(itb3_nif),
            ok
    end.

backend_ebin() ->
    case os:getenv("ITB_ERLANG_EBIN") of
        false -> default_backend_ebin();
        "" -> default_backend_ebin();
        Env -> Env
    end.

%% This module's beam lives at
%% <binding>/build/dev/erlang/libitb3/ebin/itb3_gleam_ffi.beam; the
%% sibling Erlang binding's compiled application sits five levels up
%% and over at ../erlang/_build/default/lib/libitb3/ebin.
default_backend_ebin() ->
    Here = filename:dirname(code:which(?MODULE)),
    filename:join([Here, "..", "..", "..", "..", "..",
                   "..", "erlang", "_build", "default", "lib", "libitb3",
                   "ebin"]).
