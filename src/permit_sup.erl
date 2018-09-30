-module(permit_sup).
-behaviour(supervisor).

-export([
   start_link/0,
   init/1,
   config/0,
   ephemeral/0
]).

%%
-define(CHILD(Type, I),            {I,  {I, start_link,   []}, permanent, 5000, Type, dynamic}).
-define(CHILD(Type, I, Args),      {I,  {I, start_link, Args}, permanent, 5000, Type, dynamic}).
-define(CHILD(Type, ID, I, Args),  {ID, {I, start_link, Args}, permanent, 5000, Type, dynamic}).

%%-----------------------------------------------------------------------------
%%
%% supervisor
%%
%%-----------------------------------------------------------------------------

start_link() ->
   supervisor:start_link({local, ?MODULE}, ?MODULE, []).
   
init([]) ->   
   {ok,
      {
         {one_for_one, 6, 900},
         []
      }
   }.

%%
%%
config() ->
   supervisor:start_child(?MODULE, ?CHILD(worker, permit_config)).

%%
%%
ephemeral() ->
   supervisor:start_child(?MODULE, ?CHILD(supervisor, pts, [permit, spec()])).

spec() ->
   [
      'read-through',
      {factory, temporary},
      {entity,  {permit_pubkey_io, start_link, [undefined]}}
   ].
