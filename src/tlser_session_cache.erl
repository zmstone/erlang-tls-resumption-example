-module(tlser_session_cache).

-behaviour(ssl_session_cache_api).

-export([
    init/1,
    lookup/2,
    update/3,
    delete/2,
    size/1,
    terminate/1,
    select_session/2,
    was_resumed/1
]).

-define(SERVER_CACHE, tlser_session_cache_server).
-define(CLIENT_CACHE, tlser_session_cache_client).
-define(RESUMPTION_TRACKER, tlser_resumption_tracker).

init(InitArgs) ->
    Role = proplists:get_value(role, InitArgs, unknown),
    io:format(user, "tlser_session_cache> init/1 called with role: ~p~n", [Role]),
    Name =
        case Role of
            server ->
                ?SERVER_CACHE;
            client ->
                ?CLIENT_CACHE
        end,
    _ = ets:new(Name, [named_table, ordered_set, public]),
    io:format(user, "tlser_session_cache> Created new ETS table ~p~n", [Name]),
    % Create resumption tracker table if it doesn't exist (shared across roles)
    case ets:info(?RESUMPTION_TRACKER, name) of
        undefined ->
            _ = ets:new(?RESUMPTION_TRACKER, [named_table, set, public]),
            io:format(user, "tlser_session_cache> Created resumption tracker table~n", []);
        _ ->
            ok
    end,
    Name.

lookup(Name, Key) ->
    io:format(user, "tlser_session_cache> Session lookup called with key: ~0P~n", [Key, 10]),
    case ets:lookup(Name, Key) of
        [{Key, Session}] ->
            io:format(user, "tlser_session_cache> Session lookup: FOUND session for key ~0P~n", [
                Key, 10
            ]),
            % Track that this session ID was found (indicating resumption for TLS 1.2)
            % Extract session ID from key - for server, key is just session ID; for client, it's {HostPort, SessionId}
            SessionId =
                case Key of
                    {_HostPort, Sid} when is_binary(Sid) ->
                        Sid;
                    Sid when is_binary(Sid) ->
                        Sid;
                    _ ->
                        undefined
                end,
            case SessionId of
                undefined ->
                    ok;
                _ ->
                    % Mark this session ID as used for resumption
                    ets:insert(?RESUMPTION_TRACKER, {SessionId, true})
            end,
            Session;
        [] ->
            undefined
    end.

update(Name, Key, Session) ->
    io:format(user, "tlser_session_cache> Session update called with key: ~0P~n", [Key, 10]),
    ets:insert(Name, {Key, Session}),
    io:format(user, "tlser_session_cache> Session update: STORED session for key ~0P~n", [Key, 10]),
    % Debug: show session ID if available
    case Key of
        {_PartialKey, SessionId} ->
            io:format(user, "tlser_session_cache> Session ID in key: ~0P (length: ~p)~n", [
                SessionId, 10, byte_size(SessionId)
            ]);
        _ ->
            ok
    end,
    % Show current cache size
    CacheSize = ets:info(Name, size),
    io:format(user, "tlser_session_cache> Cache size after update: ~p~n", [CacheSize]),
    true.

delete(Name, Key) ->
    ets:delete(Name, Key),
    io:format(user, "tlser_session_cache> Session delete: removed session for key ~0P~n", [Key, 2]),
    true.

size(Name) ->
    ets:info(Name, size).

terminate(Name) ->
    io:format(
        user,
        "tlser_session_cache> Terminate called for cache (table kept alive for other role)~n",
        []
    ),
    ets:delete(Name).

select_session(_Cache, _Key) ->
    io:format(user, "tlser_session_cache> select_session returns []~n", []),
    [].

% Check if a session ID was used for resumption (for TLS 1.2 detection)
was_resumed(SessionId) when is_binary(SessionId) ->
    case ets:lookup(?RESUMPTION_TRACKER, SessionId) of
        [{SessionId, true}] ->
            true;
        [] ->
            false
    end;
was_resumed(_) ->
    false.
