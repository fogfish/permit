%% @doc
%%    public / private key pair data type 
-module(permit_pubkey).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/3

  ,access/0
  ,secret/0
  ,master/0
  ,nonce/0
  % ,roles/0

  ,claims/1
  ,authenticate/2
  ,authenticate/3
  % ,authenticate/4
  ,acl/2
]).


%%
%% pubkey attributes 
access() -> lens:map(<<"access">>,  undefined).
secret() -> lens:map(<<"secret">>,  undefined).
master() -> lens:map(<<"master">>,  undefined).
nonce()  -> lens:map(<<"nonce">>,   undefined).


%%
%% create new pubkey pair 
-spec new(permit:access(), permit:secret(), permit:roles()) -> {ok, permit:pubkey()} | {error, _}.

new(Access, Secret, Claims) ->
   Nonce = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      cats:unit(#{}),
      lens:put(access(), Access, _),
      lens:put(secret(), base64url:encode(permit_hash:sign(Secret, Nonce)), _),
      lens:put(nonce(), base64url:encode(Nonce), _),
      cats:unit(maps:merge(_, Claims))
   ]}.

%%
%%
-spec claims(_) -> {ok, permit:claims()} | {error, _}.

claims(#{<<"access">> := _} = PubKey) ->
   {ok, maps:without(
         [<<"access">>, <<"secret">>, <<"master">>, <<"nonce">>], PubKey)}.


%%
%% authenticate pubkey pair and return a token with defined roles
-spec authenticate(permit:pubkey(), permit:secret()) -> {ok, permit:pubkey()} | {error, _}. 

authenticate(PubKey, Secret) ->
   [either ||
      claims(PubKey),
      authenticate(PubKey, Secret, _)
   ].

authenticate(PubKey, Secret, Claims) ->
   [either ||
      auth_signature(PubKey, Secret),
      auth_claims(_, Claims),
      cats:unit(PubKey)
   ].

auth_signature(PubKey, Secret) ->
   Nonce  = base64url:decode(lens:get(nonce(), PubKey)),
   SignA  = base64url:decode(lens:get(secret(), PubKey)),
   SignB  = permit_hash:sign(Secret, Nonce),
   case permit_hash:eq(SignA, SignB) of
      true  ->
         {ok, PubKey};
      false ->
         {error, unauthorized}
   end.

auth_claims(PubKey, Claims) ->
   [either ||
      claims(PubKey),
      cats:unit(maps:with(maps:keys(_), Claims)),
      is_non_empty_claim(_)
   ].

is_non_empty_claim(X)
 when map_size(X) =:= 0 ->
   {error, unauthorized};
is_non_empty_claim(X) ->
   {ok, X}.

%%
%% return valid list of roles
-spec acl(permit:pubkey(), permit:claims()) -> {ok, permit:claims()} | {error, _}.

acl(PubKey, Claims) ->
   [either ||
      claims(PubKey),
      cats:unit(maps:with(maps:keys(_), Claims))
   ].
