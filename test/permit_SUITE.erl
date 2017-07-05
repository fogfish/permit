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
   stateless/1, stateless_invalid_secret/1,
   pubkey/1,
   exchange/1
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
          stateless, stateless_invalid_secret, pubkey, exchange]}
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
stateless(_Config) ->
   {ok,    _} = permit:create("auth@example.com", "secret"),
   {ok, TknA} = permit:stateless("auth@example.com", "secret", 3600,
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}
   ),

   {ok, #{
      <<"sub">> := <<"auth@example.com">>,
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknA).

%%
stateless_invalid_secret(_Config) ->
   {ok, _} = permit:create("auth_secret@example.com", "secret"),
   {error, unauthorized} = permit:stateless("auth_secret@example.com", "unsecret", 3600,
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}).

%%
pubkey(_Config) ->
   {ok, _} = permit:create("pubkey@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {ok, #{
      <<"access">> := Access,
      <<"secret">> := Secret
   }} = permit:pubkey("pubkey@example.com"),
   
   {ok, Token} = permit:stateless(Access, Secret, 3600, #{uid => true}),
   {ok, #{
      <<"sub">>    := Access,
      <<"exp">>    := _,
      <<"uid">>    := true,
      <<"master">> := <<"pubkey@example.com">>
   }} = permit:validate(Token).

%%
exchange(_Config) ->
   {ok, TknA} = permit:create("issue@example.com", "secret", 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {ok, TknB} = permit:stateless(TknA, 600, 
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
exchange_invalid_claims(_Config) ->
   {ok, TknA} = permit:create("token_roles@example.com", "secret",
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {error, unauthorized} = permit:stateless(TknA, 3600, #{<<"e">> => true}).
