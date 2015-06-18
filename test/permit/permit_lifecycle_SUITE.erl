%% @doc
%%
-module(permit_lifecycle_SUITE).
-include_lib("common_test/include/ct.hrl").

%% common test
-export([
   all/0,
   groups/0,
   init_per_suite/1,
   end_per_suite/1,
   init_per_group/2,
   end_per_group/2
]).
-export([
   lifecycle/1
]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [{group, lifecycle}].

groups() ->
   [
      %%
      %% 
      {lifecycle, [parallel, {repeat, 10}], [lifecycle]}
   ].

%%%----------------------------------------------------------------------------   
%%%
%%% init
%%%
%%%----------------------------------------------------------------------------   

%%
init_per_suite(Config) ->
   ok = permit:start(),
   cluster_pending_peers(thing,    2),
   cluster_pending_peers(memcache, 2),
   ok = thingz:spawn(<<"sys">>),
   ok = memcache:spawn(<<"token">>, []),
   Config.

end_per_suite(_Config) ->
   ok.
   
%%
init_per_group(_, Config) ->
   Config.

%%
end_per_group(_, _Config) ->
   ok.

%%%----------------------------------------------------------------------------   
%%%
%%% test cases
%%%
%%%----------------------------------------------------------------------------   

lifecycle(_Config) ->
   User       = user(),
   {ok,  Tkn} = permit:signup(User, User),
   {ok, {Access, Secret}} = permit:pubkey(Tkn),
   {ok, Auth} = permit:auth(Access, Secret),
   ok         = permit:check(Auth).
   
%%%----------------------------------------------------------------------------   
%%%
%%% private
%%%
%%%----------------------------------------------------------------------------   

%%
%% pending N-cluster nodes
cluster_pending_peers(Id, N) ->
   case length(ek:members(Id)) of
      X when X < N ->
         timer:sleep(1000),
         cluster_pending_peers(Id, N);
      _ ->
         ok
   end.

user() ->
   base64:encode( crypto:rand_bytes(12) ).

