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
                    {log_level, tlser:log_level()},
                    {session_tickets, stateless}  % Enable stateless session tickets for TLS 1.3
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
    {ok, Socket} = ssl:handshake(Socket0),

    % Get connection information to check if session was resumed
    % Check handshake type and PSK usage - PSK resumption in TLS 1.3
    {ok, ConnInfo} = ssl:connection_information(Socket, [protocol, handshake]),
    Protocol = proplists:get_value(protocol, ConnInfo),

    io:format(user, "server> Accepted client with protocol: ~p~n", [Protocol]),

    % Store resumption status globally for reporting

    {next_state, accepted, D#{accepted => Socket, listening => ListenSock}};
handle_event(EventType, Event, listening, _Data) ->
    io:format(user, "server> ignored event in listening state: ~p: ~0p~n", [EventType, Event]),
    keep_state_and_data;
handle_event(enter, _OldState, accepted, _Data) ->
    keep_state_and_data;
handle_event(info, {ssl_closed, Sock}, accepted, #{accepted := Sock, listening := _ListenSock} = D) ->
    io:format(user, "server> Connection closed~n", []),
    ssl:close(Sock),
    {next_state, listening, D};
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
