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
-export([new/1, auth/1, invalid_secret/1, invalid_roles/1]).

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
         [new, auth, invalid_secret, invalid_roles]}
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
   meck:new(permit_hash, [passthrough]),
   meck:expect(permit_hash, random, fun(N) -> erlang:iolist_to_binary(lists:duplicate(N, $x)) end),

   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),

   meck:unload(permit_hash),
   
   <<"access">> = lens:get(permit_pubkey:access(), PubKey),
   undefined = lens:get(permit_pubkey:master(), PubKey),
   Nonce  = erlang:iolist_to_binary(lists:duplicate(?CONFIG_SALT, $x)),
   Nonce  = base64url:decode(lens:get(permit_pubkey:nonce(), PubKey)),
   Secret = permit_hash:sign(<<"secret">>, Nonce),
   Secret = base64url:decode(lens:get(permit_pubkey:secret(), PubKey)),
   1      = lens:get(lens:map(<<"a">>), PubKey),
   true   = lens:get(lens:map(<<"b">>), PubKey),
   <<"x">>= lens:get(lens:map(<<"c">>), PubKey).


%%
auth(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>,
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {ok, _} = permit_pubkey:authenticate(PubKey, <<"secret">>),
   {ok, _} = permit_pubkey:authenticate(PubKey, <<"secret">>, 3600),
   {ok, _} = permit_pubkey:authenticate(PubKey, <<"secret">>, 3600, #{<<"a">> => 1}),
   {ok, _} = permit_pubkey:authenticate(PubKey, <<"secret">>, 3600, #{<<"a">> => 1, <<"b">> => true}).


%%
invalid_secret(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {error, unauthorized}  = permit_pubkey:authenticate(PubKey, <<"unsecret">>).


%%
invalid_roles(_Config) ->
   {ok, PubKey} = permit_pubkey:new(<<"access">>, <<"secret">>,
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>}),
   {error, unauthorized} = permit_pubkey:authenticate(PubKey, <<"secret">>, 3600, #{<<"d">> => 1}),
   {error, unauthorized} = permit_pubkey:authenticate(PubKey, <<"secret">>, 3600, #{}).

