%% BEAM primitives the loop stress harness needs and Gleam's standard
%% library does not expose: process creation and messaging, the
%% ref-based request / reply used by the lock, atomic counters, the
%% monotonic clock, single-write output, the environment, fixed-decimal
%% float rendering, timers, the termination-signal handler and process
%% exit.
%%
%% Gleam-specific. Every entry here is a primitive, never a policy: the
%% reader / writer lock's admission rules, the stop discipline and the
%% output contract all live in the Gleam units, which pass their own
%% functions in. The one exception is the gen_event handler below,
%% which must be an Erlang callback module because that is the shape
%% the emulator's signal server accepts; all it does is set the stop
%% slot the Gleam side polls.
%%
%% The binding reaches BEAM facilities Gleam lacks through an Erlang
%% adapter already (src/itb3_gleam_ffi.erl carries env / now_us /
%% read_file / argv for the bench and eitb programs); this module is
%% the same mechanism for the utility, and it makes no libitb3 call of
%% its own.

-module(loop_native_ffi).

-behaviour(gen_event).

-export([self_pid/0, spawn_fn/1, watch_process/3, send/2, receive_any/0,
         call/2, reply/3,
         atomics_new/1, atomics_put/3, atomics_get/2,
         counters_new/1, counters_add/3, counters_get/2,
         monotonic_ns/0, write_stdout/1, write_stderr/1, getenv/1,
         read_text/1, halt/1, format_float/2, format_term/1,
         send_after/3, cancel_timer/1, random_bytes/1,
         common_prefix/2, hex_lower/1, argv/0,
         install_signal_handler/1, install_closed_pipe_filter/0,
         closed_pipe_filter/2]).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

self_pid() -> self().

spawn_fn(Fun) -> spawn(Fun).

%% Turns an abnormal exit of Pid into a Gleam-shaped message so the
%% waiting process pattern-matches one message type. A normal exit
%% sends nothing: the process reported its result itself.
watch_process(Pid, Parent, MakeMsg) ->
    spawn(fun() ->
                  MRef = monitor(process, Pid),
                  receive
                      {'DOWN', MRef, process, Pid, normal} -> ok;
                      {'DOWN', MRef, process, Pid, Reason} ->
                          Parent ! MakeMsg(Pid, format_term(Reason))
                  end
          end),
    nil.

send(Pid, Msg) ->
    Pid ! Msg,
    nil.

%% Unconditional receive: every message a loop process is sent is one
%% of its own Gleam message values, so no selection is needed.
receive_any() ->
    receive Msg -> Msg end.

%% Ref-based request / reply. The caller may have unrelated messages
%% queued (a worker exit notice, a deadline), so the reply is matched
%% on the reference rather than taken from the front of the queue.
call(Pid, MakeRequest) ->
    Ref = make_ref(),
    Pid ! MakeRequest(self(), Ref),
    receive {Ref, Reply} -> Reply end.

reply(Pid, Ref, Value) ->
    Pid ! {Ref, Value},
    nil.

atomics_new(N) -> atomics:new(N, [{signed, false}]).
atomics_put(Ref, Ix, Value) -> atomics:put(Ref, Ix, Value), nil.
atomics_get(Ref, Ix) -> atomics:get(Ref, Ix).

counters_new(N) -> counters:new(N, [write_concurrency]).
counters_add(Ref, Ix, Incr) -> counters:add(Ref, Ix, Incr), nil.
counters_get(Ref, Ix) -> counters:get(Ref, Ix).

monotonic_ns() -> erlang:monotonic_time(nanosecond).

%% One io request per line, so a line and its newline can never be
%% separated by another worker's line.
%% The two writers end the process when their device is gone. The
%% emulator ignores SIGPIPE, so a consumer that stops reading does not
%% end the run the way it ends the reference: the io server behind the
%% closed descriptor exits, the write raises, and the node would halt
%% on its own terms with exit 1. The failed write is answered with the
%% exit code the signal would have produced, 141, with nothing further
%% printed and nothing flushed.
write_stdout(Text) -> emit(standard_io, Text).
write_stderr(Text) -> emit(standard_error, Text).

emit(Device, Text) ->
    try
        io:put_chars(Device, Text), nil
    catch
        _:_ -> erlang:halt(141, [{flush, false}])
    end.

%% Keeps the emulator's own report about the closed pipe off stderr.
%% When stdout is a closed pipe the emulator's stdout writer dies of
%% epipe, and the terminal driver files an error report about it before
%% it stops; only then does the io server go away and the failed write
%% above end the process. The report therefore leaves the driver ahead
%% of the halt, and whether the default handler gets it onto stderr
%% first is a race the utility cannot win from the failing write. The
%% primary filter installed at start runs inside the driver before the
%% report reaches any handler and drops that one report — the stdout
%% writer, reason epipe — and no other, so every other event the
%% emulator files still prints.
install_closed_pipe_filter() ->
    ok = logger:add_primary_filter(loop_closed_pipe,
                                   {fun ?MODULE:closed_pipe_filter/2, none}),
    nil.

closed_pipe_filter(#{msg := {Format, [epipe]},
                     meta := #{mfa := {user_drv, _, _}}}, _) ->
    case string:prefix(Format, "Writer crashed") of
        nomatch -> ignore;
        _ -> stop
    end;
closed_pipe_filter(_Event, _) ->
    ignore.

getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

read_text(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> {ok, Bin};
        {error, _} -> {error, nil}
    end.

halt(Code) -> erlang:halt(Code, [{flush, true}]).

format_float(Value, Decimals) ->
    float_to_binary(Value * 1.0, [{decimals, Decimals}]).

format_term(Term) ->
    unicode:characters_to_binary(io_lib:format("~p", [Term])).

send_after(Ms, Pid, Msg) -> erlang:send_after(Ms, Pid, Msg).
cancel_timer(Ref) -> erlang:cancel_timer(Ref), nil.

random_bytes(N) -> crypto:strong_rand_bytes(N).

common_prefix(A, B) -> binary:longest_common_prefix([A, B]).

hex_lower(Bin) -> binary:encode_hex(Bin, lowercase).

argv() -> [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].

%% The emulator's own handler is removed first: it halts the node on
%% SIGTERM, which would end the run before the summary. SIGINT never
%% reaches BEAM code (the break handler owns it below the signal
%% server and os:set_signal/2 does not accept it), so the launcher
%% traps the interrupt and sends a termination signal instead.
install_signal_handler(Flags) ->
    _ = gen_event:delete_handler(erl_signal_server, erl_signal_handler, []),
    _ = gen_event:add_handler(erl_signal_server, ?MODULE, [Flags]),
    _ = os:set_signal(sigterm, handle),
    _ = os:set_signal(sigquit, handle),
    nil.

init([Flags]) -> {ok, Flags}.

handle_event(Signal, Flags) when Signal =:= sigterm; Signal =:= sigquit ->
    atomics:put(Flags, 1, 1),
    {ok, Flags};
handle_event(_Signal, Flags) ->
    {ok, Flags}.

handle_call(_Request, Flags) -> {ok, ok, Flags}.
handle_info(_Info, Flags) -> {ok, Flags}.
terminate(_Reason, _Flags) -> ok.
code_change(_Old, Flags, _Extra) -> {ok, Flags}.
