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
   validate/1, expired_token/1
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
         [validate, expired_token]}
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
validate(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {ok, Token}  = permit_token:stateless(PubKey, 3600, #{<<"a">> => true}),

   Access = lens:get(permit_pubkey:access(), PubKey),
   {ok, #{
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"a">>   := true
   }} = permit_token:validate(Token).

%%
expired_token(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {ok, Token}  = permit_token:stateless(PubKey, -1, #{<<"a">> => 1}),
   {error, expired} = permit_token:validate(Token).
