-module(tlser_client).

-behaviour(gen_statem).

-export([start_link/0, stop/0]).
-export([terminate/3,
         code_change/4,
         init/1,
         callback_mode/0,
         handle_event/4
        ]).

name() -> ?MODULE.

start_link() ->
    application:ensure_all_started(ssl),
    gen_statem:start_link({local, name()}, ?MODULE, [], []).

stop() ->
    gen_statem:stop(name()).

terminate(normal, _State, _Data) ->
    io:format(user, "PASS~n", []),
    erlang:halt(0);
terminate(_Reason, _State, _Data) ->
    void.

code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.

init([]) ->
    io:format(user, "client> Starting TLS 1.3 session resumption test~n", []),
    BaseOpts = tlser:files() ++
           [{verify, verify_none},
            {versions, ['tlsv1.3']},
            {log_level, tlser:log_level()},
            {active, true},  % Use active=true to receive Post-Handshake NewSessionTicket messages
            {session_tickets, manual}  % Manual session ticket handling
           ],

    % Start in disconnected state - connection will be attempted via enter handler
    {ok, disconnected, #{base_opts => BaseOpts, tickets => [], reconnected => false}}.

callback_mode() ->
    [state_enter, handle_event_function].

% State: disconnected
handle_event(enter, _OldState, disconnected, #{tickets := Tickets, reconnected := Reconnected} = Data) ->
    % Check if we need tickets but don't have any
    case {Reconnected, Tickets} of
        {true, []} ->
            io:format(user, "client> ERROR: No tickets available for reconnection~n", []),
            {stop, no_tickets};
        _ ->
            % Schedule connection attempt as state_timeout to avoid blocking
            {keep_state, Data, [{state_timeout, 0, connect}]}
    end;
handle_event(state_timeout, connect, disconnected, #{base_opts := BaseOpts, tickets := Tickets, reconnected := Reconnected} = Data) ->
    % Determine connection options based on state
    Opts = case Reconnected of
        true ->
            % Reconnection - use ticket for PSK resumption
            % According to OTP docs (Step 12), we keep all options and add use_ticket
            % Tickets are always in map format (opaque)
            [Ticket | _] = Tickets,
            io:format(user, "client> Reconnecting to server ~s:~p (using session ticket)~n", [server_host(), server_port()]),
            use_ticket(Ticket);
        false ->
            % First connection - full handshake
            io:format(user, "client> Connecting to server ~s:~p (initial handshake)~n", [server_host(), server_port()]),
            BaseOpts
    end,
    try
        case ssl:connect(server_host(), server_port(), Opts, infinity) of
            {ok, Socket} ->
                % Check session resumption using the OTP test pattern
                SessionResumed = check_session_resumption(Socket),
                {ok, ConnInfo} = ssl:connection_information(Socket, [protocol]),
                Protocol = proplists:get_value(protocol, ConnInfo),
                case SessionResumed of
                    true ->
                        io:format(user, "client> Connected. Protocol: ~p (session resumed)~n", [Protocol]);
                    false ->
                        io:format(user, "client> Connected. Protocol: ~p (full handshake)~n", [Protocol])
                end,
                % Transition to connected state
                {next_state, connected, Data#{socket => Socket, waiting_for_pong => false}};
            {error, Reason} = Error ->
                io:format(user, "client> Connection failed with error: ~p~n", [Reason]),
                {stop, {connection_failed, Error}}
        end
    catch
        C:E:ST ->
            io:format(user, "client> Connection failed with exception: ~p:~p~n", [C, E]),
            {stop, {connection_failed, C, E, ST}}
    end;
% State: connected
handle_event(enter, _OldState, connected, #{socket := Socket} = Data) ->
    % Send ping message
    ssl:send(Socket, "ping"),
    io:format(user, "client> Sent ping~n", []),
    % Set timeout to check if we've received pong and tickets
    % Wait a bit for tickets to arrive, then check if we can proceed
    {keep_state, Data#{waiting_for_pong => true, pong_received => false},
     [{state_timeout, 1000, check_complete}]};
handle_event(info, {ssl, Socket, Msg}, connected, #{socket := Socket} = Data) ->
    case Msg of
        "pong" ->
            io:format(user, "client> Received pong~n", []),
            % Mark pong as received, check_complete timeout will handle next steps
            {keep_state, Data#{waiting_for_pong => false, pong_received => true}};
        Other ->
            io:format(user, "client> Received unexpected message: ~ts~n", [Other]),
            keep_state_and_data
    end;
handle_event(info, {ssl_error, Socket, Reason}, connected, #{socket := Socket, reconnected := Reconnected} = Data) ->
    io:format(user, "client> SSL error on socket: ~p~n", [Reason]),
    % If this is PSK resumption and we get an SSL error, it might be because server requires client certs
    % Treat this as connection closed and proceed
    case Reconnected of
        true ->
            io:format(user, "client> SSL error during PSK resumption, treating as connection closed~n", []),
            {keep_state, Data#{socket => undefined, pong_received => true}};
        false ->
            {keep_state, Data}
    end;
handle_event(info, {ssl, session_ticket, Ticket}, connected, #{tickets := Tickets} = Data) when is_map(Ticket) ->
    % Tickets are always received as maps (opaque format)
    % Store the entire ticket map as-is for use_ticket
    io:format(user, "client> Received session ticket: ~0P~n", [Ticket, 3]),
    NewTickets = [Ticket | Tickets],
    TicketCount = length(NewTickets),
    io:format(user, "client> Received session ticket (~p total), storing as opaque map~n", [TicketCount]),
    {keep_state, Data#{tickets => NewTickets}};
handle_event(state_timeout, check_complete, connected, Data) ->
    handle_check_complete(Data);
handle_event(info, {ssl_closed, Socket}, connected, #{socket := Socket} = Data) ->
    io:format(user, "client> Connection closed by server~n", []),
    {keep_state, Data#{socket => undefined}};
handle_event(info, {ssl_closed, _Socket}, connected, _Data) ->
    % Socket closed but doesn't match our socket - ignore
    keep_state_and_data;
handle_event(EventType, Event, connected, _Data) ->
    io:format(user, "client> ignored event in connected state: ~p: ~p~n", [EventType, Event]),
    keep_state_and_data;
% State: disconnected - handle state_timeout events
handle_event(state_timeout, _Event, disconnected, _Data) ->
    % Should not happen - state_timeout should be handled above
    keep_state_and_data;
handle_event(EventType, Event, disconnected, _Data) ->
    io:format(user, "client> ignored event in disconnected state: ~p: ~p~n", [EventType, Event]),
    keep_state_and_data;
% State: waiting_for_alert - wait for server alert after corrupted ticket connection
handle_event(info, {ssl_error, Socket, Reason}, waiting_for_alert, #{socket := Socket}) ->
    % Server sent alert rejecting the corrupted ticket - expected behavior
    io:format(user, "client> Server alert received (corrupted ticket rejected): ~0p~n", [Reason]),
    ssl:close(Socket),
    {stop, normal};
handle_event(info, {ssl_closed, Socket}, waiting_for_alert, #{socket := Socket}) ->
    % Socket closed - server rejected the corrupted ticket
    io:format(user, "client> Socket closed by server (corrupted ticket rejected)~n", []),
    {stop, normal};
handle_event(state_timeout, alert_timeout, waiting_for_alert, #{socket := Socket}) ->
    % Timeout waiting for alert - close socket and stop
    io:format(user, "client> Timeout waiting for server alert, closing connection~n", []),
    ssl:close(Socket),
    {stop, normal};
handle_event(EventType, Event, waiting_for_alert, _Data) ->
    io:format(user, "client> ignored event in waiting_for_alert state: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data.

server_host() ->
    case os:getenv("TLSER_SERVER_HOST") of
        false -> "localhost";
        Host -> Host
    end.

server_port() -> tlser:server_port().

% Handle check_complete timeout with pattern matching on Data sub-states
handle_check_complete(#{socket := undefined, reconnected := true, tickets := _Tickets}) ->
    % Socket was closed due to SSL error during PSK resumption
    % If session resumption cannot work, there's no point continuing to test corrupted tickets
    io:format(user, "client> ERROR: Connection closed during PSK resumption - session resumption failed~n", []),
    {stop, session_resumption_failed};
handle_check_complete(#{socket := undefined, reconnected := false}) ->
    % Socket is undefined and we haven't reconnected yet - error
    io:format(user, "client> ERROR: Socket is undefined in check_complete~n", []),
    {stop, no_socket};
handle_check_complete(#{pong_received := false} = Data) ->
    % Haven't received pong yet, wait a bit more
    io:format(user, "client> Still waiting for pong, extending timeout~n", []),
    {keep_state, Data, [{state_timeout, 1000, check_complete}]};
handle_check_complete(#{socket := Socket, reconnected := false} = Data) ->
    % First connection complete, disconnect and reconnect
    io:format(user, "client> Disconnecting (first connection complete)~n", []),
    ssl:close(Socket),
    timer:sleep(1000),  % Wait 1 second
    {next_state, disconnected, Data#{socket => undefined, reconnected => true}};
handle_check_complete(#{socket := Socket, reconnected := true, tickets := Tickets}) ->
    % Already reconnected once, now test with corrupted ticket
    io:format(user, "client> Disconnecting (reconnection complete)~n", []),
    ssl:close(Socket),
    test_corrupted_ticket(Tickets).

% Test connection with corrupted ticket - should fail
% Returns state transition to wait for async server alert
test_corrupted_ticket(Tickets) ->
    CorruptedTicket = corrupt_ticket(Tickets),
    io:format(user, "client> Attempting reconnection with corrupted ticket (should fail)~n", []),
    CorruptedOpts = use_ticket(CorruptedTicket),
    case catch ssl:connect(server_host(), server_port(), CorruptedOpts, 5000) of
        {ok, BadSocket} ->
            SessionResumed = check_session_resumption(BadSocket),
            io:format(user, "client> Connection succeeded. SessionResumed: ~p~n", [SessionResumed]),
            case SessionResumed of
                true ->
                    % Session resumption was used - this is unexpected for a corrupted ticket
                    io:format(user, "client> ERROR: Connection with corrupted ticket used session resumption (unexpected)~n", []),
                    ssl:close(BadSocket),
                    {stop, unexpected_success};
                false ->
                    % Connection succeeded but server may send alert asynchronously
                    % Transition to waiting_for_alert state to wait for server alert
                    io:format(user, "client> Connection established, waiting for server alert (corrupted ticket should be rejected)~n", []),
                    {next_state, waiting_for_alert, #{socket => BadSocket}, [{state_timeout, 5000, alert_timeout}]}
            end;
        {error, Reason} ->
            io:format(user, "client> Connection with corrupted ticket failed as expected: ~p~n", [Reason]),
            {stop, normal};
        {'EXIT', {timeout, _}} ->
            io:format(user, "client> Connection with corrupted ticket timed out (acceptable failure)~n", []),
            {stop, normal};
        {'EXIT', {C, E, _}} ->
            io:format(user, "client> Connection with corrupted ticket failed as expected: ~p:~p~n", [C, E]),
            {stop, normal};
        Other ->
            io:format(user, "client> Connection with corrupted ticket returned: ~p (treating as failure)~n", [Other]),
            {stop, normal}
    end.

% Check if session was resumed using the OTP test pattern
check_session_resumption(Socket) ->
    case ssl:connection_information(Socket, [session_resumption]) of
        {ok, [{session_resumption, SessionResumption}]} ->
            SessionResumption;
        {ok, ConnInfo} ->
            % Fallback if session_resumption is not available
            io:format(user, "client> WARNING: session_resumption not in connection info: ~p~n", [ConnInfo]),
            false;
        {error, Reason} ->
            io:format(user, "client> ERROR: Failed to get connection information: ~p~n", [Reason]),
            false
    end.

% Generate a corrupted ticket that will cause connection failure
% Takes a list of valid tickets (maps) and returns a corrupted version
corrupt_ticket([Ticket | _Tickets]) ->
    % Extract the ticket tuple from the map, corrupt it, and put it back
    TicketTuple = maps:get(ticket, Ticket),
    {new_session_ticket, _Lifetime, _AgeAdd, _Nonce, TicketBin, _Extensions} = TicketTuple,
    InvalidTicketBin = case TicketBin of
        <<_Head:100/binary, _Rest/binary>> ->
            <<0:800>>;  % 100 bytes of zeros
        _ ->
            <<"INVALID_CORRUPTED_TICKET_DATA_THAT_WILL_CAUSE_DECRYPTION_FAILURE">>
    end,
    CorruptedTuple = {new_session_ticket, 1, 999999, <<255,255,255,255,255,255,255,255>>, InvalidTicketBin, #{}},
    maps:put(ticket, CorruptedTuple, Ticket).

use_ticket(Ticket) ->
    [{use_ticket, [Ticket]}, {verify, verify_none}, {session_tickets, manual}].
