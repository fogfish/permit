%% @doc
%%    public / private key management abstraction  
-module(permit_pubkey).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/3
  ,access/0
  ,secret/0
  ,master/0
  ,nonce/0
  ,roles/0
  ,authenticate/2
  ,authenticate/3
]).


%%
%% create new pubkey pair 
new(Access, Secret, Roles) ->
   Nonce = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      lens:put(access(), Access, #{}),
      lens:put(master(), Access, _),
      lens:put(secret(), permit_hash:sign(Secret, Nonce), _),
      lens:put(nonce(), Nonce, _),
      lens:put(roles(), roles(Roles), _)
   ]}.

%%
%% 
access() -> lens:map(<<"access">>,  undefined).
secret() -> lens:map(<<"secret">>,  undefined).
master() -> lens:map(<<"master">>,  undefined).
nonce()  -> lens:map(<<"nonce">>,   undefined).
roles()  -> lens:map(<<"roles">>,   undefined).

%%
%% authenticate pubkey pair, return a token with defined roles
authenticate(PubKey, Secret) ->
   authenticate(PubKey, Secret, lens:get(roles(), PubKey)).

authenticate(PubKey, Secret, Roles) ->
   Nonce  = lens:get(nonce(),  PubKey),
   SignA  = lens:get(secret(), PubKey),
   SignB  = permit_hash:sign(Secret, Nonce),
   case permit_hash:eq(SignA, SignB) of
      true  ->
         A = gb_sets:from_list([scalar:s(X) || X <- Roles]),
         B = gb_sets:from_list([scalar:s(X) || X <- lens:get(permit_pubkey:roles(), PubKey)]),
         token(PubKey, gb_sets:to_list(gb_sets:intersection(A, B)));
      false ->
         {error, unauthorized}
   end.

token(_, []) ->
   {error, unauthorized};

token(PubKey, Roles) ->
   {ok, permit_token:encode(
      permit_token:new(PubKey, ?CONFIG_TTL_ACCESS, Roles)
   )}.

roles(Roles) ->
   [scalar:s(X) || X <- Roles].

