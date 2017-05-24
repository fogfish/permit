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
  ,scope/0
  ,authenticate/2
]).


%%
%% create new pubkey certificate 
new(Access, Secret, Scope) ->
   Nonce = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      lens:put(access(), Access, #{}),
      lens:put(secret(), permit_hash:sign(Secret, Nonce), _),
      lens:put(nonce(), Nonce, _),
      lens:put(scope(), Scope, _)
   ]}.

%%
%% 
access() -> lens:map(<<"access">>,  undefined).
secret() -> lens:map(<<"secret">>,  undefined).
master() -> lens:map(<<"master">>,  undefined).
nonce()  -> lens:map(<<"nonce">>,   undefined).
scope()  -> lens:map(<<"scope">>,   undefined).

%%
%% authenticate certificate, return a token with given scope
authenticate(Entity, Secret) ->
   Access = lens:get(access(), Entity), 
   Master = lens:get(master(), Entity), 
   Nonce  = lens:get(nonce(),  Entity),
   Scope  = lens:get(scope(),  Entity),
   SignA  = lens:get(secret(), Entity),
   SignB  = permit_hash:sign(Secret, Nonce),
   case permit_hash:eq(SignA, SignB) of
      true  ->
         {ok, token(Master, Access, Scope)};
      false ->
         {error, unauthorized}   
   end.

token(Master, Access, Scope) ->
   permit_token:encode(
      permit_token:new(Master, Access, Scope)
   ).

