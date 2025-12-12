-module(tlser_server).

-behaviour(gen_statem).

-export([start_link/0, stop/0]).
-export([
    terminate/3,
    code_change/4,
    init/1,
    callback_mode/0,
    handle_event/4
]).

-export([
    handle_ping/4,
    extract_client_id/1,
    process_ping_message/4,
    verify_resumption_status/5,
    update_client_sessions/4,
    check_session_resumption/2
]).

name() -> ?MODULE.

start_link() ->
    gen_statem:start_link({local, name()}, ?MODULE, [], []).

stop() ->
    gen_statem:stop(name()).

terminate(_Reason, _State, _Data) ->
    void.

code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.

init([]) ->
    io:format(user, "server> Starting TLS session resumption test server (TLS 1.2 and 1.3)~n", []),
    {ok, ListenSock} =
        ssl:listen(
            tlser:server_port(),
            tlser:files() ++
                [
                    {reuseaddr, true},
                    % Verify peer certificates when provided
                    {verify, verify_peer},
                    % Require client certificates
                    {fail_if_no_peer_cert, true},
                    % Support both TLS 1.2 and 1.3
                    {versions, ['tlsv1.3', 'tlsv1.2']},
                    {active, true},
                    {log_level, tlser:log_level()},
                    % Enable TLS 1.2 session resumption (uses session_cb from config)
                    {reuse_sessions, true},
                    % Enable stateless session tickets with certificate info for TLS 1.3
                    {session_tickets, stateless_with_cert}
                    % TLS 1.2 session resumption uses external storage configured via application env (session_cb)
                ]
        ),
    io:format(user, "server> listening on port ~p~n", [tlser:server_port()]),
    {ok, _State = listening, _Data = #{listening => ListenSock, client_sessions => #{}}}.

callback_mode() ->
    [state_enter, handle_event_function].

handle_event(enter, _OldState, listening, #{listening := _ListenSock} = D) ->
    % Schedule accepting a connection as a state_timeout
    {keep_state, D, [{state_timeout, 0, accept_connection}]};
handle_event(state_timeout, accept_connection, listening, #{listening := ListenSock} = D) ->
    % Accept connection (this will block until a connection arrives)
    {ok, Socket0} = ssl:transport_accept(ListenSock),

    % Attempt handshake - it may fail if client doesn't provide certificates
    case ssl:handshake(Socket0) of
        {ok, Socket} ->
            % Handshake succeeded - get session information
            % Session resumption will be determined when we receive the ping message with client ID
            {ok, ConnInfo} = ssl:connection_information(Socket, [protocol, session_id]),
            Protocol = proplists:get_value(protocol, ConnInfo),
            SessionId = proplists:get_value(session_id, ConnInfo, <<>>),

            io:format(user, "server> Accepted client with protocol: ~p~n", [Protocol]),
            io:format(user, "server> Session ID: ~P~n", [SessionId, 10]),
            % Schedule accepting another connection to handle concurrent connections
            ClientSessions = maps:get(client_sessions, D, #{}),
            {next_state, accepted,
                D#{
                    accepted => Socket,
                    listening => ListenSock,
                    client_sessions => ClientSessions
                },
                [
                    {state_timeout, 0, accept_connection}
                ]};
        {error, Reason} ->
            % Handshake failed - log error, close socket, and continue accepting
            io:format(user, "server> Handshake failed: ~0p~n", [Reason]),
            ssl:close(Socket0),
            % Schedule another accept to continue listening
            {next_state, listening, D, [{state_timeout, 0, accept_connection}]}
    end;
handle_event(state_timeout, accept_connection, listening, _Data) ->
    % Timeout may fire after state change - ignore silently
    keep_state_and_data;
handle_event(EventType, Event, listening, _Data) ->
    io:format(user, "server> ignored event in listening state: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data;
handle_event(enter, _OldState, accepted, #{listening := _ListenSock} = D) ->
    % Continue accepting new connections even when we have an active connection
    {keep_state, D, [{state_timeout, 0, accept_connection}]};
handle_event(enter, _OldState, accepted, _Data) ->
    keep_state_and_data;
handle_event(info, {ssl_closed, Sock}, accepted, #{accepted := Sock, listening := ListenSock} = D) ->
    io:format(user, "server> Connection closed~n", []),
    ssl:close(Sock),
    % Schedule accepting another connection
    {next_state, listening, D#{accepted => undefined, listening => ListenSock}, [
        {state_timeout, 0, accept_connection}
    ]};
handle_event(
    info, {ssl, Sock, Msg}, accepted, #{accepted := Sock, client_sessions := ClientSessions} = Data
) ->
    io:format(user, "server> Received message: ~0p~n", [Msg]),
    handle_ping(Sock, Msg, ClientSessions, Data);
handle_event(EventType, Event, accepted, _Data) ->
    io:format(user, "server> ignored event: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data.

% Extract client ID from ping- prefixed messages
% Returns {ok, ClientId} if message starts with "ping-", {error, not_ping} otherwise
extract_client_id(Msg) ->
    case Msg of
        <<"ping-", ClientId/binary>> ->
            {ok, ClientId};
        _ ->
            {error, not_ping}
    end.

% Handle ping messages from clients
handle_ping(Sock, Msg, ClientSessions, Data) ->
    case extract_client_id(iolist_to_binary(Msg)) of
        {ok, ClientId} ->
            process_ping_message(Sock, ClientId, ClientSessions, Data);
        {error, not_ping} ->
            io:format(user, "server> Ignored message: ~ts~n", [Msg]),
            keep_state_and_data
    end.

% Process ping message with extracted client ID
process_ping_message(Sock, ClientId, ClientSessions, Data) ->
    io:format(user, "server> Received ping from client ID: ~s~n", [ClientId]),
    % Get client info (ping count and stored session ID)
    ClientInfo = maps:get(ClientId, ClientSessions, #{ping_count => 0, session_id => undefined}),
    PingCount = maps:get(ping_count, ClientInfo, 0),
    StoredSessionId = maps:get(session_id, ClientInfo, undefined),
    NewPingCount = PingCount + 1,
    ExpectedResumption = NewPingCount > 1,
    % Check if session was resumed
    SessionResumed = check_session_resumption(Sock, StoredSessionId),
    % Get current session ID for storage
    {ok, ConnInfo} = ssl:connection_information(Sock, [session_id]),
    CurrentSessionId = proplists:get_value(session_id, ConnInfo, <<>>),
    % Verify resumption based on expected state
    verify_resumption_status(
        ClientId, ExpectedResumption, SessionResumed, StoredSessionId, CurrentSessionId
    ),
    % Update client sessions and send pong
    NewClientSessions = update_client_sessions(
        ClientId, CurrentSessionId, NewPingCount, ClientSessions
    ),
    ssl:send(Sock, "pong"),
    io:format(user, "server> Sent pong~n", []),
    {keep_state, Data#{client_sessions => NewClientSessions}}.

% Check if session was resumed (works for both TLS 1.2 and 1.3)
check_session_resumption(Socket, StoredSessionId) ->
    case ssl:connection_information(Socket, [protocol, session_id, session_resumption]) of
        {ok, ConnInfo} ->
            Protocol = proplists:get_value(protocol, ConnInfo),
            CurrentSessionId = proplists:get_value(session_id, ConnInfo, <<>>),
            SessionResumption = proplists:get_value(session_resumption, ConnInfo, undefined),
            case Protocol of
                'tlsv1.2' ->
                    % For TLS 1.2, compare session IDs
                    case {StoredSessionId, CurrentSessionId} of
                        {undefined, _} ->
                            false;
                        {_, <<>>} ->
                            false;
                        {StoredSessionId, CurrentSessionId} when
                            StoredSessionId =:= CurrentSessionId
                        ->
                            true;
                        _ ->
                            false
                    end;
                _ ->
                    % For TLS 1.3, use session_resumption flag
                    case SessionResumption of
                        undefined -> false;
                        Resumed -> Resumed
                    end
            end;
        {error, Reason} ->
            io:format(user, "server> ERROR: Failed to get connection information: ~p~n", [Reason]),
            false
    end.

% Verify resumption status and log results
verify_resumption_status(ClientId, true, SessionResumed, StoredSessionId, CurrentSessionId) ->
    % Expected resumption - verify it happened
    case SessionResumed of
        true ->
            io:format(
                user,
                "server> Session resumption verified - session RESUMED~n",
                []
            ),
            io:format(
                user,
                "server> Session resumption verified for client ID: ~s~n",
                [ClientId]
            );
        false ->
            io:format(
                user,
                "server> ERROR: Expected resumption but session was not resumed~n",
                []
            ),
            case StoredSessionId of
                undefined ->
                    ok;
                _ ->
                    io:format(user, "server> Stored session ID: ~P~n", [StoredSessionId, 10]),
                    io:format(user, "server> Current session ID: ~P~n", [CurrentSessionId, 10])
            end,
            io:format(
                user,
                "server> TEST FAILED: Session resumption did not work for client ID: ~s~n",
                [ClientId]
            )
    end;
verify_resumption_status(ClientId, false, _SessionResumed, _StoredSessionId, _CurrentSessionId) ->
    % First connection - full handshake expected
    io:format(
        user,
        "server> First connection from client ID: ~s - storing session ID~n",
        [ClientId]
    ).

% Update client sessions map with new ping count and session ID
update_client_sessions(ClientId, CurrentSessionId, NewPingCount, ClientSessions) ->
    NewClientInfo = #{ping_count => NewPingCount, session_id => CurrentSessionId},
    maps:put(ClientId, NewClientInfo, ClientSessions).
