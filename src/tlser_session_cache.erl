-module(tlser_session_cache).

-behaviour(ssl_session_cache_api).

-export([init/1,
         lookup/2,
         update/3,
         delete/2,
         size/1,
         terminate/1]).

init(InitArgs) ->
    % SSL calls init/1 twice - once for client role, once for server role
    % Since it's a named table, the CacheRef is the atom ?MODULE
    case proplists:get_value(role, InitArgs) of
        server ->
            % Initialize named ETS table for session storage
            % Returns the table name (atom ?MODULE) as CacheRef
            io:format(user, "tlser_session_cache> init/1 called as server~n", []),
            ets:new(?MODULE, [named_table, ordered_set, public]);
        client ->
            % Client role - return dummy (client doesn't use this cache)
            % Client node doesn't have SSL app env configured, so this won't be called
            io:format(user, "tlser_session_cache> init/1 called as client (ignored)~n", []),
            dummy_client_cache;
        _ ->
            % Unknown role - return dummy cache ref
            io:format(user, "tlser_session_cache> init/1 called with unknown role: ~0p~n", [InitArgs]),
            dummy_cache
    end.

% API: lookup(CacheRef, Key) -> Session | undefined
% CacheRef is ?MODULE (atom) for server-side calls
% Key format: {PartialKey, SessionId} where PartialKey is {Host, Port} or Port
lookup(?MODULE, Key) ->
    io:format(user, "tlser_session_cache> Session lookup called with key: ~0P~n", [Key, 10]),
    case ets:lookup(?MODULE, Key) of
        [{Key, Session}] ->
            io:format(user, "tlser_session_cache> Session lookup: FOUND session for key ~0P~n", [Key, 10]),
            Session;
        [] ->
            io:format(user, "tlser_session_cache> Session lookup: NOT FOUND for key ~0P~n", [Key, 10]),
            % Debug: show all keys in cache
            AllKeys = ets:tab2list(?MODULE),
            io:format(user, "tlser_session_cache> Cache currently contains ~p entries~n", [length(AllKeys)]),
            case AllKeys of
                [] ->
                    io:format(user, "tlser_session_cache> Cache is empty~n", []);
                _ ->
                    io:format(user, "tlser_session_cache> Cache keys: ~0P~n", [AllKeys, 5])
            end,
            undefined
    end;
lookup(CacheRef, Key) ->
    % Non-server cache ref (shouldn't happen on server side)
    io:format(user, "tlser_session_cache> Session lookup: non-server cache ref ~p, key ~0P~n", [CacheRef, Key, 5]),
    undefined.

% API: update(CacheRef, Key, Session) -> DoNotCare
% CacheRef is ?MODULE (atom) for server-side calls
% Key format: {PartialKey, SessionId} where PartialKey is {Host, Port} or Port
update(?MODULE, Key, Session) ->
    io:format(user, "tlser_session_cache> Session update called with key: ~0P~n", [Key, 10]),
    ets:insert(?MODULE, {Key, Session}),
    io:format(user, "tlser_session_cache> Session update: STORED session for key ~0P~n", [Key, 10]),
    % Debug: show session ID if available
    case Key of
        {_PartialKey, SessionId} ->
            io:format(user, "tlser_session_cache> Session ID in key: ~0P (length: ~p)~n", [SessionId, 10, byte_size(SessionId)]);
        _ ->
            ok
    end,
    ok;
update(CacheRef, Key, _Session) ->
    % Non-server cache ref (shouldn't happen on server side)
    io:format(user, "tlser_session_cache> Session update: non-server cache ref ~p, key ~0P~n", [CacheRef, Key, 5]),
    ok.

% API: delete(CacheRef, Key) -> DoNotCare
% CacheRef is ?MODULE (atom) for server-side calls
delete(?MODULE, Key) ->
    ets:delete(?MODULE, Key),
    io:format(user, "tlser_session_cache> Session delete: removed session for key ~0P~n", [Key, 2]),
    ok;
delete(_CacheRef, _Key) ->
    % Non-server cache ref (shouldn't happen on server side)
    ok.

% API: size(CacheRef) -> Size
% CacheRef is ?MODULE (atom) for server-side calls
size(?MODULE) ->
    ets:info(?MODULE, size);
size(_CacheRef) ->
    % Non-server cache ref (shouldn't happen on server side)
    0.

% API: terminate(CacheRef) -> DoNotCare
% CacheRef is ?MODULE (atom) for server-side calls
terminate(?MODULE) ->
    ets:delete(?MODULE),
    io:format(user, "tlser_session_cache> Terminated external session cache~n", []),
    ok;
terminate(_CacheRef) ->
    % Non-server cache ref (shouldn't happen on server side)
    ok.
