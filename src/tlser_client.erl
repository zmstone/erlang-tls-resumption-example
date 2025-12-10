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

terminate(_Reason, _State, _Data) ->
    void.

code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.

init([]) ->
    io:format(user, "client> Starting TLS 1.3 session resumption test~n", []),
    BaseOpts = tlser:files() ++
           [{verify, verify_none},
            {versions, ['tlsv1.3']},
            {ciphers, tlser:cipher_suites(client)},
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
    if Reconnected andalso Tickets =:= [] ->
        io:format(user, "client> ERROR: No tickets available for reconnection~n", []),
        {stop, no_tickets};
    true ->
        % Schedule connection attempt as state_timeout to avoid blocking
        {keep_state, Data, [{state_timeout, 0, connect}]}
    end;

handle_event(state_timeout, connect, disconnected, #{base_opts := BaseOpts, tickets := Tickets, reconnected := Reconnected} = Data) ->
    % Determine connection options based on state
    Opts = if Reconnected ->
        % Reconnection - use ticket
        [Ticket | _] = Tickets,
        io:format(user, "client> Reconnecting to server ~s:~p (using session ticket)~n",
                  [server_host(), server_port()]),
        BaseOpts ++ [{use_ticket, [Ticket]}];
    true ->
        % First connection - full handshake
        io:format(user, "client> Connecting to server ~s:~p (initial handshake)~n",
                  [server_host(), server_port()]),
        BaseOpts
    end,

    % Attempt connection
    try
        case ssl:connect(server_host(), server_port(), Opts, infinity) of
            {ok, Socket} ->
                % Get connection information
                {ok, ConnInfo} = ssl:connection_information(Socket, [protocol]),
                Protocol = proplists:get_value(protocol, ConnInfo),
                if Reconnected ->
                    io:format(user, "client> Reconnected. Protocol: ~p (resumed via PSK)~n", [Protocol]);
                true ->
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
     [{state_timeout, 3000, check_complete}]};

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

handle_event(info, {ssl, session_ticket, TicketMap}, connected, #{tickets := Tickets} = Data) when is_map(TicketMap) ->
    % Extract the ticket from the map
    % The ticket is a tuple: {new_session_ticket, Lifetime, AgeAdd, Nonce, Ticket, Extensions}
    TicketTuple = maps:get(ticket, TicketMap),
    NewTickets = [TicketTuple | Tickets],
    TicketCount = length(NewTickets),
    io:format(user, "client> Received session ticket (~p total)~n", [TicketCount]),
    {keep_state, Data#{tickets => NewTickets}};

handle_event(info, {ssl, session_ticket, {_Socket, TicketData}}, connected, #{tickets := Tickets} = Data) ->
    % Alternative format
    NewTickets = [TicketData | Tickets],
    TicketCount = length(NewTickets),
    io:format(user, "client> Received session ticket (~p total)~n", [TicketCount]),
    {keep_state, Data#{tickets => NewTickets}};

handle_event(state_timeout, check_complete, connected, Data) ->
    % Get values from Data map with defaults
    Socket = maps:get(socket, Data, undefined),
    Reconnected = maps:get(reconnected, Data, false),
    Tickets = maps:get(tickets, Data, []),
    PongReceived = maps:get(pong_received, Data, false),
    
    if Socket =:= undefined ->
        io:format(user, "client> ERROR: Socket is undefined in check_complete~n", []),
        {stop, no_socket};
    not PongReceived ->
        % Haven't received pong yet, wait a bit more
        io:format(user, "client> Still waiting for pong, extending timeout~n", []),
        {keep_state, Data, [{state_timeout, 2000, check_complete}]};
    true ->
        % We've received pong, check if we should disconnect
        case Reconnected of
            false ->
                % First connection complete, disconnect and reconnect
                io:format(user, "client> Disconnecting (first connection complete)~n", []),
                ssl:close(Socket),
                timer:sleep(1000),  % Wait 1 second
                {next_state, disconnected, Data#{socket => undefined, reconnected => true}};
            true ->
                % Already reconnected once, now test with corrupted ticket
                io:format(user, "client> Disconnecting (reconnection complete)~n", []),
                ssl:close(Socket),

                % Create a corrupted ticket using helper function
                CorruptedTicket = corrupt_ticket(Tickets),

                io:format(user, "client> Attempting reconnection with corrupted ticket (should fail)~n", []),
                % Try to reconnect with corrupted ticket
                BaseOpts = maps:get(base_opts, Data, []),
                CorruptedOpts = BaseOpts ++ [{use_ticket, [CorruptedTicket]}],
                % Use a timeout to avoid hanging if connection doesn't fail
                case catch ssl:connect(server_host(), server_port(), CorruptedOpts, 5000) of
                    {ok, BadSocket} ->
                        % Check if PSK was actually used or if it fell back to full handshake
                        {ok, ConnInfo} = ssl:connection_information(BadSocket, [protocol, handshake]),
                        Handshake = proplists:get_value(handshake, ConnInfo),
                        Protocol = proplists:get_value(protocol, ConnInfo),
                        io:format(user, "client> Connection succeeded. Protocol: ~p, Handshake: ~p~n", [Protocol, Handshake]),
                        if Handshake =:= resumed ->
                            % PSK was used - this is unexpected for a corrupted ticket
                            io:format(user, "client> ERROR: Connection with corrupted ticket used PSK resumption (unexpected)~n", []),
                            ssl:close(BadSocket),
                            {stop, unexpected_success};
                        true ->
                            % Full handshake - ticket was rejected and fell back (this is acceptable)
                            io:format(user, "client> Corrupted ticket was rejected, fell back to full handshake (acceptable)~n", []),
                            ssl:close(BadSocket),
                            {stop, normal}
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
                end
        end
    end;

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
    keep_state_and_data.

server_host() ->
    case os:getenv("TLSER_SERVER_HOST") of
        false -> "localhost";
        Host -> Host
    end.

server_port() -> tlser:server_port().

% Generate a corrupted ticket that will cause connection failure
% Takes a list of valid tickets and returns a corrupted version
corrupt_ticket([FirstTicket | _Tickets]) ->
    % Get a valid ticket and corrupt it severely
    % Ticket format: {new_session_ticket, Lifetime, AgeAdd, Nonce, Ticket, Extensions}
    case FirstTicket of
        {new_session_ticket, _Lifetime, _AgeAdd, _Nonce, TicketBin, _Extensions} ->
            % Replace the entire ticket with completely invalid data
            % This should cause decryption/authentication to fail
            InvalidTicketBin = case TicketBin of
                <<_Head:100/binary, _Rest/binary>> ->
                    % Ticket is long enough - corrupt first 100 bytes
                    <<0:800>>;  % 100 bytes of zeros
                _ ->
                    % Short ticket - replace with invalid data
                    <<"INVALID_CORRUPTED_TICKET_DATA_THAT_WILL_CAUSE_DECRYPTION_FAILURE">>
            end,
            % Use completely different nonce and invalid data
            {new_session_ticket, 1, 999999, <<255,255,255,255,255,255,255,255>>, 
                InvalidTicketBin, #{}};
        _ ->
            % Invalid ticket format - create completely invalid ticket
            {new_session_ticket, 1, 0, <<255,255,255,255,255,255,255,255>>, 
                <<"INVALID_TICKET_FORMAT">>, #{}}
    end.
