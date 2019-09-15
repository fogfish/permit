%% @doc
%%
-module(permit_pubkey_SUITE).
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
%%% unit tests
%%%
%%%----------------------------------------------------------------------------   

%%
new(_) ->
   Nonce  = <<"abcdef">>,
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   Access = {iri, <<"example.com">>, <<"joe">>},
   Secret = <<"secret">>,
   
   HSecret = base64url:encode(permit_hash:sign(Secret, Nonce)),
   HNonce  = base64url:encode(Nonce),

   meck:new(permit_hash, [passthrough]),
   meck:expect(permit_hash, random, fun(_) -> Nonce end),

   {ok,
      #pubkey{
         id     = Access
      ,  secret = HSecret
      ,  nonce  = HNonce
      ,  claims = Claims
      }
   } = permit_pubkey:new(Access, Secret, Claims),

   meck:unload(permit_hash).


%%
auth(_Config) ->
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   Access = {iri, <<"example.com">>, <<"joe">>},
   Secret = <<"secret">>,

   {ok, PubKey} = permit_pubkey:new(Access, Secret, Claims),
   {ok, _} = permit_pubkey:authenticate(PubKey, Secret).

   % {ok, _} = permit_pubkey:authenticate(PubKey, Secret, Claims),
   % {ok, _} = permit_pubkey:authenticate(PubKey, Secret, maps:without([<<"c">>], Claims)),
   % {ok, _} = permit_pubkey:authenticate(PubKey, Secret, maps:without([<<"b">>, <<"c">>], Claims)).


%%
invalid_secret(_Config) ->
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   Access = {iri, <<"example.com">>, <<"joe">>},
   Secret = <<"secret">>,

   {ok, PubKey} = permit_pubkey:new(Access, Secret, Claims),
   {error, unauthorized}  = permit_pubkey:authenticate(PubKey, <<"unsecret">>).


%%
% invalid_claims(_Config) ->
%    Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
%    Access = {iri, <<"example.com">>, <<"joe">>},
%    Secret = <<"secret">>,

%    {ok, PubKey} = permit_pubkey:new(Access, Secret, Claims),
%    {error, unauthorized} = permit_pubkey:authenticate(PubKey, Secret, #{<<"d">> => 1}),
%    {error, unauthorized} = permit_pubkey:authenticate(PubKey, Secret, #{}).
