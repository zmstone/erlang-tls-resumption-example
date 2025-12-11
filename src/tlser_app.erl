%%%-------------------------------------------------------------------
%% @doc tlser public API
%% @end
%%%-------------------------------------------------------------------

-module(tlser_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    io:format(user, "tlser_app> SSL started, checking session cache callback initialization~n", []),
    tlser_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
