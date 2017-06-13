%% @doc
%%
-module(permit_token_SUITE).
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
-export([
   check/1, invalid_roles/1, expired_token/1, invalid_secret/1
]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [
      {group, token}
   ].

groups() ->
   [
      {token, [parallel], 
         [check, invalid_roles, expired_token, invalid_secret]}
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

%%   
check(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [a]),

   Access = lens:get(permit_pubkey:access(), PubKey),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   {ok, #{
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"a">>   := true
   }} = permit_token:check(Token, Secret).

%%
invalid_roles(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {error, invalid_roles} = permit_token:new(PubKey, 3600, [d]).

%%
expired_token(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, -1, [a]),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   {error, expired} = permit_token:check(Token, Secret).

%%
invalid_secret(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [a]),
   {error, invalid_signature} = permit_token:check(Token, <<"unsecret">>).
