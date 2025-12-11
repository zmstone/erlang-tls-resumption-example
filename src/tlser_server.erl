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
                    {verify, verify_peer},  % Verify peer certificates when provided
                    {fail_if_no_peer_cert, true},  % Require client certificates
                    {versions, ['tlsv1.3']},
                    {active, true},
                    {log_level, tlser:log_level()},
                    {session_tickets, stateless_with_cert}  % Enable stateless session tickets with certificate info for TLS 1.3
                   ]),
    io:format(user, "server> listening on port ~p~n", [tlser:server_port()]),
    {ok, _State = listening, _Data = #{listening => ListenSock}}.

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
            % Handshake succeeded - check session resumption using the OTP test pattern
            case ssl:connection_information(Socket, [session_resumption]) of
                {ok, [{session_resumption, SessionResumed}]} ->
                    {ok, ConnInfo} = ssl:connection_information(Socket, [protocol]),
                    Protocol = proplists:get_value(protocol, ConnInfo),
                    case SessionResumed of
                        true ->
                            io:format(user, "server> Accepted client with protocol: ~p (session resumed)~n", [Protocol]);
                        false ->
                            io:format(user, "server> Accepted client with protocol: ~p (full handshake)~n", [Protocol])
                    end,
                    % Inspect certificate information using ssl:peercert for resumed vs full handshake sessions
                    case SessionResumed of
                        true ->
                            io:format(user, "server> Checking ssl:peercert for RESUMED session:~n", []);
                        false ->
                            io:format(user, "server> Checking ssl:peercert for FULL HANDSHAKE session:~n", [])
                    end,
                    case ssl:peercert(Socket) of
                        {ok, Cert} ->
                            io:format(user, "server> ssl:peercert returned certificate: ~0P~n", [Cert, 3]);
                        {error, no_peercert} ->
                            io:format(user, "server> ssl:peercert returned: {error, no_peercert}~n", []);
                        {error, Reason} ->
                            io:format(user, "server> ssl:peercert returned error: ~p~n", [Reason])
                    end;
                {ok, ConnInfo} ->
                    % Fallback if session_resumption is not in the expected format
                    io:format(user, "server> WARNING: session_resumption not in expected format. ConnInfo: ~p~n", [ConnInfo]),
                    Protocol = proplists:get_value(protocol, ConnInfo, unknown),
                    io:format(user, "server> Accepted client with protocol: ~p (session_resumption check failed)~n", [Protocol]);
                {error, Reason} ->
                    io:format(user, "server> WARNING: Failed to get session_resumption info: ~p~n", [Reason])
            end,
            % Schedule accepting another connection to handle concurrent connections
            {next_state, accepted, D#{accepted => Socket, listening => ListenSock}, [{state_timeout, 0, accept_connection}]};
        {error, Reason} ->
            % Handshake failed - log error, close socket, and continue accepting
            io:format(user, "server> Handshake failed: ~0p~n", [Reason]),
            ssl:close(Socket0),
            % Schedule another accept to continue listening
            {next_state, listening, D, [{state_timeout, 0, accept_connection}]}
    end;
handle_event(EventType, Event, listening, _Data) ->
    io:format(user, "server> ignored event in listening state: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data;
handle_event(enter, _OldState, accepted, #{listening := ListenSock} = D) ->
    % Continue accepting new connections even when we have an active connection
    {keep_state, D, [{state_timeout, 0, accept_connection}]};
handle_event(enter, _OldState, accepted, _Data) ->
    keep_state_and_data;
handle_event(info, {ssl_closed, Sock}, accepted, #{accepted := Sock, listening := ListenSock} = D) ->
    io:format(user, "server> Connection closed~n", []),
    ssl:close(Sock),
    % Schedule accepting another connection
    {next_state, listening, maps:remove(accepted, D), [{state_timeout, 0, accept_connection}]};
handle_event(info, {ssl, Sock, Msg}, accepted, #{accepted := Sock}) ->
    io:format(user, "server> Received message: ~ts~n", [Msg]),
    case Msg of
        "ping" ->
            ssl:send(Sock, "pong"),
            io:format(user, "server> Sent pong~n", []);
        _ ->
            io:format(user, "server> Ignored message: ~ts~n", [Msg]),
            ok
    end,
    keep_state_and_data;
handle_event(EventType, Event, accepted, _Data) ->
    io:format(user, "server> ignored event: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data.
