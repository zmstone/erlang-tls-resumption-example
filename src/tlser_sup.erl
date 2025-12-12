%%%-------------------------------------------------------------------
%% @doc tlser top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(tlser_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([]) ->
    SupFlags = #{
        strategy => one_for_all,
        intensity => 0,
        period => 1
    },
    ChildSpec =
        case tlser:which_side() of
            server ->
                #{
                    id => tlser_server,
                    start => {tlser_server, start_link, []}
                };
            client ->
                #{
                    id => tlser_client,
                    start => {tlser_client, start_link, []}
                }
        end,
    {ok, {SupFlags, [ChildSpec]}}.

%% internal functions
