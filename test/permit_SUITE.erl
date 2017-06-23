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
   issue/1, issue_invalid_roles/1
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
          auth, auth_invalid_secret, auth_invalid_roles, pubkey, issue, issue_invalid_roles]}
   ].

%%%----------------------------------------------------------------------------   
%%%
%%% init
%%%
%%%----------------------------------------------------------------------------   
init_per_suite(Config) ->
   permit:start(),
   {ok, Pid} = permit:ephemeral(),
   erlang:unlink(Pid),
   Config.


end_per_suite(_Config) ->
   erlang:exit(whereis(permit), kill),
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
      <<"sub">> := <<"create@example.com">>,
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(Token).

%%
create_conflict(_Config) ->
   {ok,_Token} = permit:create("conflict@example.com", "secret"),
   {error,  _} = permit:create("conflict@example.com", "secret").

%%
update(_Config) ->
   {ok, TokenA} = permit:create("update@example.com", "secret"),
   {ok, #{
      <<"sub">> := <<"update@example.com">>,
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(TokenA),

   {ok, TokenB} = permit:update("update@example.com", "newsecret"),
   {ok, #{
      <<"sub">> := <<"update@example.com">>, 
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(TokenB),
   {error, invalid_signature} = permit:validate(TokenA).

update_notfound(_Config) ->
   {error, not_found} = permit:update("not_found@example.com", "secret").

%%
lookup(_Config) ->
   {ok, _} = permit:create("lookup@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {ok, #{
      <<"access">> := <<"lookup@example.com">>, 
      <<"secret">> := _,
      <<"nonce">>  := _,
      <<"a">>      := 1,
      <<"b">>      := true,
      <<"c">>      := <<"x">>
   }} = permit:lookup("lookup@example.com").

%%
lookup_notfound(_Config) ->
   {error, not_found} = permit:lookup("not_found@example.com").

%%
revoke(_Config) ->
   {ok, Token} = permit:create("revoke@example.com", "secret"),
   {ok, _} = permit:validate(Token),
   {ok, _} = permit:revoke("revoke@example.com"),
   {error, not_found} = permit:validate(Token).   

%%
auth(_Config) ->
   {ok,    _} = permit:create("auth@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),

   {ok, TknA} = permit:auth("auth@example.com", "secret"),
   {ok, #{
      <<"sub">> := <<"auth@example.com">>,
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknA),

   {ok, TknB} = permit:auth("auth@example.com", "secret", 3600),
   {ok, #{
      <<"sub">> := <<"auth@example.com">>, 
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknB),

   {ok, TknC} = permit:auth("auth@example.com", "secret", 3600, 
      #{<<"a">> => 5, <<"d">> => true}),
   {ok, #{
      <<"sub">> := <<"auth@example.com">>, 
      <<"exp">> := _,
      <<"a">>   := 5,
      <<"d">>   := true
   }} = permit:validate(TknC).

%%
auth_invalid_secret(_Config) ->
   {ok, _} = permit:create("auth_secret@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {error, unauthorized} = permit:auth("auth_secret@example.com", "unsecret").

%%
auth_invalid_roles(_Config) ->
   {ok, _} = permit:create("auth_roles@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {error, unauthorized} = permit:auth("auth_roles@example.com", "secret", 3600, #{<<"e">> => true}).

%%
pubkey(_Config) ->
   {ok, Master} = permit:create("pubkey@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {ok, #{
      <<"access">> := Access,
      <<"secret">> := Secret
   }} = permit:pubkey(Master),
   
   {ok, Token} = permit:auth(Access, Secret),
   {ok, #{
      <<"sub">>    := Access,
      <<"exp">>    := _,
      <<"uid">>    := true,
      <<"master">> := <<"pubkey@example.com">>
   }} = permit:validate(Token).

%%
issue(_Config) ->
   {ok, TknA} = permit:create("issue@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {ok, TknB} = permit:issue("issue@example.com", 600, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {ok, #{
      <<"sub">> := <<"issue@example.com">>,
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknB).

%%
issue_invalid_roles(_Config) ->
   {ok, TknA} = permit:create("token_roles@example.com", "secret",
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {error, unauthorized} = permit:issue("token_roles@example.com", 3600, #{<<"e">> => true}).
