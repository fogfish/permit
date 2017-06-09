%% @doc
%%
-module(permit_pubkey_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("permit/src/permit.hrl").

%% common test
-export([
   all/0,
   groups/0,
   init_per_suite/1,
   end_per_suite/1,
   init_per_group/2,
   end_per_group/2
]).

%% unit tests
-export([new/1]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [
      {group, pubkey}
   ].

groups() ->
   [
      %%
      %% 
      {pubkey, [parallel], 
         [new]}
   ].

%%%----------------------------------------------------------------------------   
%%%
%%% init
%%%
%%%----------------------------------------------------------------------------   
init_per_suite(Config) ->
   Config.


end_per_suite(_Config) ->
   ok.

%% 
%%
init_per_group(_, Config) ->
   Config.

end_per_group(_, _Config) ->
   ok.


%%%----------------------------------------------------------------------------   
%%%
%%% unit tests
%%%
%%%----------------------------------------------------------------------------   

new(_Config) ->
   meck:new(permit_hash, [passthrough]),
   meck:expect(permit_hash, random, fun(N) -> erlang:iolist_to_binary(lists:duplicate(N, $x)) end),

   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),

   meck:unload(permit_hash),
   
   <<"access">> = lens:get(permit_pubkey:access(), PubKey),
   <<"access">> = lens:get(permit_pubkey:master(), PubKey),
   Nonce  = erlang:iolist_to_binary(lists:duplicate(?CONFIG_SALT, $x)),
   Nonce  = lens:get(permit_pubkey:nonce(), PubKey),
   Secret = permit_hash:sign(<<"secret">>, Nonce),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   [<<"a">>, <<"b">>, <<"c">>] = lens:get(permit_pubkey:roles(), PubKey).

      

