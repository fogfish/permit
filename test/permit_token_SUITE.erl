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
   new/1, check/1, invalid_roles/1, expired_token/1, invalid_secret/1, 
   breach_version/1, breach_roles/1, breach_ttl/1, breach_access/1, breach_master/1
]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [
      {group, token}
     ,{group, security}
   ].

groups() ->
   [
      %%
      %% 
      {token, [parallel], 
         [new, check, invalid_roles, expired_token, invalid_secret]}

     ,{security, [parallel],
         [breach_version, breach_roles, breach_ttl, breach_access, breach_master]
      }
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
new(_Config) ->
   Now = 1230000000,
   meck:new(tempus, [passthrough]),
   meck:expect(tempus, s, fun() -> Now end),
   meck:new(permit_hash, [passthrough]),
   meck:expect(permit_hash, random, fun(N) -> erlang:iolist_to_binary(lists:duplicate(N, $x)) end),
   
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [a]),

   meck:unload(tempus),
   meck:unload(permit_hash),
    
   ?VSN = lens:get(permit_token:version(), Token),
   3600 = lens:get(permit_token:ttl(), Token) - Now,
   [<<"a">>]  = lens:get(permit_token:roles(), Token),
   Access = lens:get(permit_pubkey:access(), PubKey),
   Access = lens:get(permit_token:access(), Token),
   Master = lens:get(permit_pubkey:master(), PubKey),
   Master = lens:get(permit_token:master(), Token),
   <<"6c768c062736daa59169c3159f765aefb084c5f58994056cd458a49f8f9c1fae">> = lens:get(permit_token:signature(), Token).

%%   
check(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Access = lens:get(permit_pubkey:access(), PubKey),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   {ok, #{
      <<"access">> := Access,
      <<"roles">>  := [<<"d">>]
   }} = permit_token:check(Token, Secret, [d]).

%%
invalid_roles(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   {error, scopes} = permit_token:check(Token, Secret, [a]).

%%
expired_token(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, -1, [d]),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   {error, expired} = permit_token:check(Token, Secret, [d]).

%%
invalid_secret(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, -1, [d]),
   {error, unauthorized} = permit_token:check(Token, <<"unsecret">>, [d]).

%%
breach_version(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Secret = lens:get(permit_pubkey:secret(), PubKey),
   NewTkn = lens:put(permit_token:version(), 0, Token),
   {error, unauthorized} = permit_token:check(NewTkn, Secret, [d]).
   
%%
breach_roles(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Secret = lens:get(permit_pubkey:secret(), PubKey),
   NewTkn = lens:put(permit_token:roles(), [<<"e">>], Token),
   {error, unauthorized} = permit_token:check(NewTkn, Secret, [e]).

%%
breach_ttl(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Secret = lens:get(permit_pubkey:secret(), PubKey),
   NewTkn = lens:put(permit_token:ttl(), 1240000000, Token),
   {error, unauthorized} = permit_token:check(NewTkn, Secret, [d]).

%%
breach_access(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Secret = lens:get(permit_pubkey:secret(), PubKey),
   NewTkn = lens:put(permit_token:access(), <<"evil">>, Token),
   {error, unauthorized} = permit_token:check(NewTkn, Secret, [d]).

%%
breach_master(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, [a, b, c]),
   {ok, Token}  = permit_token:new(PubKey, 3600, [d]),

   Secret = lens:get(permit_pubkey:secret(), PubKey),
   NewTkn = lens:put(permit_token:master(), <<"evil">>, Token),
   {error, unauthorized} = permit_token:check(NewTkn, Secret, [d]).
   
