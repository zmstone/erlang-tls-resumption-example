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
    io:format(user, "server> ", []),
    {ok, ListenSock} =
    ssl:listen(tlser:server_port(),
                  tlser:files() ++
                  [ {reuseaddr, true},
                    {verify, verify_peer},
                    {versions, tlser:versions()},
                    {ciphers, tlser:cipher_suites(server)},
                    {active, true},
                    {log_level, tlser:log_level()}
                   ]),
    {ok, _State = listening, _Data = #{listening => ListenSock}}.

callback_mode() ->
    [state_enter, handle_event_function].

handle_event(enter, _OldState, listening, #{listening := ListenSock} = D) ->
    io:format(user, "server> listening~n", []),
    {ok, Socket0} = ssl:transport_accept(ListenSock),
    {ok, Socket} = ssl:handshake(Socket0),
    io:format(user, "server> accepted one client: negotiated_protocol?=~0p~n", [ssl:negotiated_protocol(Socket)]),
    {next_state, listening, D, [{state_timeout, 0, {accepted, Socket}}]};
handle_event(state_timeout, {accepted, Sock}, listening, D) ->
    {next_state, accepted, D#{accepted => Sock}};
handle_event(enter, _OldState, accepted, _Data) ->
    keep_state_and_data;
handle_event(info, {ssl_closed, Sock}, accepted, #{accepted := Sock} = D) ->
    ssl:close(Sock),
    {next_state, listening, D};
handle_event(info, {ssl, Sock, Msg}, accepted, #{accepted := Sock}) ->
    io:format(user, "server> received message: ~ts~n", [Msg]),
    case Msg of
        "ping" ->
            ssl:send(Sock, "pong");
        _ ->
            io:format(user, "server> ignored message: ~ts~n", [Msg]),
            ok
    end,
    keep_state_and_data;
handle_event(EventType, Event, accepted, Data) ->
    io:format(user, "server> ignored event: ~p: ~0p~n~p", [EventType, Event,Data]),
    keep_state_and_data.
