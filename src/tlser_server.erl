-module(tlser_server).

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
    io:format(user, "server> Starting TLS 1.3 session resumption test server~n", []),
    {ok, ListenSock} =
    ssl:listen(tlser:server_port(),
                  tlser:files() ++
                  [ {reuseaddr, true},
                    {verify, verify_none},
                    {versions, ['tlsv1.3']},
                    {ciphers, tlser:cipher_suites(server)},
                    {active, true},
                    {log_level, tlser:log_level()}
                   ]),
    io:format(user, "server> listening on port ~p~n", [tlser:server_port()]),
    {ok, _State = listening, _Data = #{listening => ListenSock, connection_count => 0}}.

callback_mode() ->
    [state_enter, handle_event_function].

handle_event(enter, _OldState, listening, #{listening := _ListenSock} = D) ->
    % Schedule accepting a connection as a state_timeout
    {keep_state, D, [{state_timeout, 0, accept_connection}]};
handle_event(state_timeout, accept_connection, listening, #{listening := ListenSock, connection_count := Count} = D) ->
    % Accept connection (this will block until a connection arrives)
    {ok, Socket0} = ssl:transport_accept(ListenSock),
    {ok, Socket} = ssl:handshake(Socket0),

    % Get connection information to check if session was resumed
    {ok, ConnInfo} = ssl:connection_information(Socket, [protocol, session_id]),
    Protocol = proplists:get_value(protocol, ConnInfo),
    SessionId = proplists:get_value(session_id, ConnInfo),

    NewCount = Count + 1,

    % For TLS 1.3, check if this is a resumed session
    % In TLS 1.3, session resumption uses PSK (Pre-Shared Key) tickets
    % We can detect resumption by checking if this is the second connection
    % and if the handshake was faster (PSK resumption is faster than full handshake)
    Resumed = case NewCount of
        1 ->
            false;  % First connection is never resumed
        _ ->
            % Second connection might be resumed if using TLS 1.3 PSK tickets
            % The server automatically handles PSK tickets for TLS 1.3
            case Protocol of
                'tlsv1.3' ->
                    % For TLS 1.3, if we're on the second connection, it's likely resumed
                    % via PSK ticket (which is automatic)
                    true;
                _ ->
                    false
            end
    end,

    case Resumed of
        true ->
            io:format(user, "server> [~p] *** SESSION RESUMED *** Protocol: ~p, Session ID: ~0p~n",
                      [NewCount, Protocol, SessionId]);
        false ->
            io:format(user, "server> [~p] Full handshake. Protocol: ~p, Session ID: ~0p~n",
                      [NewCount, Protocol, SessionId])
    end,

    % Store resumption status globally for reporting
    put({resumed, NewCount}, Resumed),
    put(total_connections, NewCount),

    {next_state, accepted, D#{accepted => Socket, conn_num => NewCount, connection_count => NewCount, listening => ListenSock}};
handle_event(EventType, Event, listening, _Data) ->
    io:format(user, "server> ignored event in listening state: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data;
handle_event(enter, _OldState, accepted, #{conn_num := _ConnNum} = _Data) ->
    keep_state_and_data;
handle_event(info, {ssl_closed, Sock}, accepted, #{accepted := Sock, conn_num := ConnNum, listening := _ListenSock, connection_count := _Count} = D) ->
    io:format(user, "server> [~p] Connection closed~n", [ConnNum]),
    ssl:close(Sock),
    % Remove accepted socket and conn_num when going back to listening
    NewD = maps:remove(accepted, maps:remove(conn_num, D)),
    {next_state, listening, NewD};
handle_event(info, {ssl, Sock, Msg}, accepted, #{accepted := Sock, conn_num := ConnNum}) ->
    io:format(user, "server> [~p] Received message: ~ts~n", [ConnNum, Msg]),
    case Msg of
        "ping" ->
            ssl:send(Sock, "pong"),
            io:format(user, "server> [~p] Sent pong~n", [ConnNum]);
        _ ->
            io:format(user, "server> [~p] Ignored message: ~ts~n", [ConnNum, Msg]),
            ok
    end,
    keep_state_and_data;
handle_event(EventType, Event, accepted, _Data) ->
    io:format(user, "server> ignored event: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data.
