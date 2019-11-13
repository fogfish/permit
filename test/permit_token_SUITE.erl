%% @doc
%%
-module(permit_token_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("permit/src/permit.hrl").

-compile(export_all).

%%
all() ->
   [Test || {Test, NAry} <- ?MODULE:module_info(exports), 
      Test =/= module_info,
      Test =/= init_per_suite,
      Test =/= end_per_suite,
      NAry =:= 1
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

%%%----------------------------------------------------------------------------   
%%%
%%% unit tests
%%%
%%%----------------------------------------------------------------------------   

%%   
validate(_Config) ->
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   Access = {iri, <<"9bj7YMYRYzHaB8Zblqih0Q">>, <<"joe@example.com">>},
   Secret = <<"secret">>,

   {ok, PubKey} = permit_pubkey:new(Access, Secret, Claims),
   {ok, Token}  = permit_token:stateless(PubKey, 3600, #{<<"a">> => true}),

   {ok, #{
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"a">>   := true
   }} = permit_token:validate(Token).

%%
expired_token(_Config) ->
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   Access = {iri, <<"9bj7YMYRYzHaB8Zblqih0Q">>, <<"joe@example.com">>},
   Secret = <<"secret">>,

   {ok, PubKey} = permit_pubkey:new(Access, Secret, Claims),
   {ok, Token}  = permit_token:stateless(PubKey, -1, #{<<"a">> => 1}),
   {error, expired} = permit_token:validate(Token).
