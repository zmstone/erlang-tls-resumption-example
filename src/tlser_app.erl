%%%-------------------------------------------------------------------
%% @doc tlser public API
%% @end
%%%-------------------------------------------------------------------

-module(tlser_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    % Configure SSL application for TLS 1.3 session tickets
    % Set number of tickets to send and their lifetime
    application:set_env(ssl, session_tickets_number, 2),
    application:set_env(ssl, session_tickets_lifetime, 3600),  % 1 hour
    tlser_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
