%% @doc
%%
-module(permit_SUITE).
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

%% unit tests
-export([
   create/1, create_conflict/1,
   update/1, update_notfound/1,
   lookup/1, lookup_notfound/1,
   revoke/1,
   auth/1, auth_invalid_secret/1, auth_invalid_roles/1,
   pubkey/1,
   token/1, token_invalid_roles/1
]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [
      {group, libapi}
   ].

groups() ->
   [
      %%
      %% 
      {libapi, [parallel], 
         [create, create_conflict, update, update_notfound, lookup, lookup_notfound, revoke, 
          auth, auth_invalid_secret, auth_invalid_roles, pubkey, token, token_invalid_roles]}
   ].

%%%----------------------------------------------------------------------------   
%%%
%%% init
%%%
%%%----------------------------------------------------------------------------   
init_per_suite(Config) ->
   permit:start(),
   Config.


end_per_suite(_Config) ->
   application:stop(permit),
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
create(_Config) ->
   {ok, Token} = permit:create("create@example.com", "secret"),
   {ok, #{
      <<"access">> := <<"create@example.com">>, 
      <<"master">> := <<"create@example.com">>, 
      <<"roles">>  := [<<"uid">>]
   }} = permit:validate(Token).

%%
create_conflict(_Config) ->
   {ok,_Token} = permit:create("conflict@example.com", "secret"),
   {error,  _} = permit:create("conflict@example.com", "secret").

%%
update(_Config) ->
   {ok, TokenA} = permit:create("update@example.com", "secret"),
   {ok, #{
      <<"access">> := <<"update@example.com">>, 
      <<"master">> := <<"update@example.com">>, 
      <<"roles">>  := [<<"uid">>]
   }} = permit:validate(TokenA),

   {ok, TokenB} = permit:update("update@example.com", "newsecret"),
   {ok, #{
      <<"access">> := <<"update@example.com">>, 
      <<"master">> := <<"update@example.com">>, 
      <<"roles">>  := [<<"uid">>]
   }} = permit:validate(TokenB),
   {error, unauthorized} =  permit:validate(TokenA).

update_notfound(_Config) ->
   {error, not_found} = permit:update("not_found@example.com", "secret").

%%
lookup(_Config) ->
   {ok, _} = permit:create("lookup@example.com", "secret"),
   {ok, Token} = permit:lookup("lookup@example.com", "secret"),
   {ok, #{
      <<"access">> := <<"lookup@example.com">>, 
      <<"master">> := <<"lookup@example.com">>, 
      <<"roles">>  := [<<"uid">>]
   }} = permit:validate(Token).

%%
lookup_notfound(_Config) ->
   {error, not_found} = permit:lookup("not_found@example.com", "secret").

%%
revoke(_Config) ->
   {ok, Token} = permit:create("revoke@example.com", "secret"),
   {ok, _} = permit:validate(Token),
   {ok, _} = permit:revoke("revoke@example.com"),
   {error, not_found} = permit:validate(Token).   

%%
auth(_Config) ->
   {ok,    _} = permit:create("auth@example.com", "secret", [a, b, c, d]),

   {ok, TknA} = permit:auth("auth@example.com", "secret"),
   {ok, #{
      <<"access">> := <<"auth@example.com">>, 
      <<"master">> := <<"auth@example.com">>, 
      <<"roles">>  := [<<"a">>, <<"b">>, <<"c">>, <<"d">>]
   }} = permit:validate(TknA),

   {ok, TknB} = permit:auth("auth@example.com", "secret", 3600),
   {ok, #{
      <<"access">> := <<"auth@example.com">>, 
      <<"master">> := <<"auth@example.com">>, 
      <<"roles">>  := [<<"a">>, <<"b">>, <<"c">>, <<"d">>]
   }} = permit:validate(TknB),

   {ok, TknC} = permit:auth("auth@example.com", "secret", 3600, [a, d]),
   {ok, #{
      <<"access">> := <<"auth@example.com">>, 
      <<"master">> := <<"auth@example.com">>, 
      <<"roles">>  := [<<"a">>, <<"d">>]
   }} = permit:validate(TknC).

%%
auth_invalid_secret(_Config) ->
   {ok, _} = permit:create("auth_secret@example.com", "secret", [a, b, c, d]),
   {error, unauthorized} = permit:auth("auth_secret@example.com", "unsecret").

%%
auth_invalid_roles(_Config) ->
   {ok, _} = permit:create("auth_roles@example.com", "secret", [a, b, c, d]),
   {error, scopes} = permit:auth("auth_secret@example.com", "secret", 3600, [e]).

%%
pubkey(_Config) ->
   {ok, Master} = permit:create("pubkey@example.com", "secret", [a, b, c, d]),
   {ok, #{
      <<"access">> := Access,
      <<"secret">> := Secret
   }} = permit:pubkey(Master),
   
   {ok, Token} = permit:auth(Access, Secret),
   {ok, #{
      <<"access">> := Access,
      <<"master">> := <<"pubkey@example.com">>,
      <<"roles">>  := [<<"access">>]
   }} = permit:validate(Token).

%%
token(_Config) ->
   {ok, TknA} = permit:create("token@example.com", "secret", [a, b, c, d]),   
   {ok, TknB} = permit:token(TknA),
   {ok, #{
      <<"access">> := <<"token@example.com">>,
      <<"master">> := <<"token@example.com">>,
      <<"roles">>  := [<<"a">>, <<"b">>, <<"c">>, <<"d">>]
   }} = permit:validate(TknB).

%%
token_invalid_roles(_Config) ->
   {ok, TknA} = permit:create("token_roles@example.com", "secret", [a, b, c, d]),   
   {error, scopes} = permit:token(TknA, 3600, [e]).
