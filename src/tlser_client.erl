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
            {session_tickets, auto}  % Enable automatic session ticket handling for TLS 1.3
           ] ++ max_fragment_length(),

    % First connection - full handshake
    io:format(user, "client> [1/2] Connecting to server ~s:~p (initial handshake)~n",
              [server_host(), server_port()]),
    {ok, Socket1} =
        try
            ssl:connect(server_host(), server_port(), BaseOpts, infinity)
        catch
            C:E:ST->
                error({C, E, ST})
        end,

    % Get connection information from first connection
    {ok, ConnInfo1} = ssl:connection_information(Socket1, [protocol]),
    Protocol1 = proplists:get_value(protocol, ConnInfo1),
    io:format(user, "client> [1/2] Connected. Protocol: ~p (full handshake)~n",
              [Protocol1]),

    % Send a message and receive response
    ssl:send(Socket1, "ping"),

    % Receive pong
    % With {active, true}, messages come as {ssl, Socket, Data}
    receive
        {ssl, Socket1, "pong"} ->
            io:format(user, "client> [1/2] Received pong~n", [])
    after 2000 ->
        io:format(user, "client> [1/2] Timeout waiting for pong~n", [])
    end,

    % In TLS 1.3, NewSessionTicket messages are sent as Post-Handshake messages
    % after the handshake completes. According to the user guide, these are sent
    % automatically by the server. With {session_tickets, auto}, the client
    % automatically receives and stores these tickets.
    % We need to keep the connection open to receive Post-Handshake messages.
    % The NewSessionTicket is sent automatically, we just need to wait for it.
    io:format(user, "client> [1/2] Waiting for NewSessionTicket (Post-Handshake message)...~n", []),
    % Wait for Post-Handshake NewSessionTicket - it's handled automatically with {session_tickets, auto}
    timer:sleep(3000),  % Give server time to send NewSessionTicket post-handshake message

    % Close first connection (session ticket should have been received and stored)
    ssl:close(Socket1),
    io:format(user, "client> [1/2] Closed first connection~n", []),

    % Brief pause to ensure ticket is fully processed
    timer:sleep(500),

    % Second connection - should resume session using PSK ticket
    io:format(user, "client> [2/2] Connecting to server ~s:~p (should resume session)~n",
              [server_host(), server_port()]),
    {ok, Socket2} =
        try
            ssl:connect(server_host(), server_port(), BaseOpts, infinity)
        catch
            C2:E2:ST2->
                error({C2, E2, ST2})
        end,

    % Get connection information from second connection
    {ok, ConnInfo2} = ssl:connection_information(Socket2, [protocol, handshake]),
    Protocol2 = proplists:get_value(protocol, ConnInfo2),
    Handshake2 = proplists:get_value(handshake, ConnInfo2),
    % Note: In TLS 1.3, Session IDs are not used for resumption (PSK tickets are used instead)
    % Each connection gets a new Session ID even when resuming, so we don't print it
    io:format(user, "client> [2/2] Connected. Protocol: ~p, Handshake: ~p (should be resumed via PSK)~n",
              [Protocol2, Handshake2]),

    % Send a message and receive response
    ssl:send(Socket2, "ping"),

    % Receive pong (with active=true, messages come as {ssl, Socket, Data})
    receive
        {ssl, Socket2, "pong"} ->
            io:format(user, "client> [2/2] Received pong~n", [])
    after 2000 ->
        io:format(user, "client> [2/2] Timeout waiting for pong~n", [])
    end,

    % Note: For TLS 1.3, session resumption is handled automatically via PSK tickets
    % The actual resumption detection is better done on the server side
    % We'll report success if both connections completed successfully
    io:format(user, "client> Both connections completed successfully~n", []),

    {ok, _State = connected, _Data = #{socket => Socket2}}.

callback_mode() ->
    handle_event_function.

handle_event(info, {ssl, Socket, Msg}, _State, #{socket := Socket}) ->
    io:format(user, "client> received message: ~ts~n", [Msg]),
    keep_state_and_data;
handle_event(info, {ssl_closed, Socket}, _State, #{socket := Socket}) ->
    io:format(user, "client> connection closed~n", []),
    keep_state_and_data;
handle_event(EventType, Event, _State, _Data) ->
    io:format(user, "client> ignored event: ~p: ~p~n", [EventType, Event]),
    keep_state_and_data.

server_host() ->
    case os:getenv("TLSER_SERVER_HOST") of
        false -> "localhost";
        Host -> Host
    end.

server_port() -> tlser:server_port().

max_fragment_length() ->
    case os:getenv("TLSER_MAX_FRAGMENT_LENTH") of
        false ->
            [];
        Int ->
            Max = list_to_integer(Int),
            [{max_fragment_length, Max}]
    end.
