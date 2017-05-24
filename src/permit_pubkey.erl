%% @doc
%%    public / private key management abstraction  
-module(permit_pubkey).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/2
  ,access/0
  ,secret/0
  ,master/0
  ,nonsense/0
  ,authenticate/3
]).


%%
%% create new pubkey certificate 
new(Access, Secret) ->
   Nonsense = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      lens:put(access(), Access, #{}),
      lens:put(secret(), permit_hash:sign(Secret, Nonsense), _),
      lens:put(nonsense(), Nonsense, _)
   ]}.

%%
%% 
access()   -> lens:map(<<"access">>,  undefined).
secret()   -> lens:map(<<"secret">>,  undefined).
master()   -> lens:map(<<"master">>,  undefined).
nonsense() -> lens:map(<<"nonsense">>, undefined).

%%
%% authenticate certificate, return a token with given scope
authenticate(Entity, Secret, Scope) ->
   Access   = lens:get(access(), Entity), 
   Master   = lens:get(master(), Entity), 
   Nonsense = lens:get(nonsense(), Entity),
   SignA    = lens:get(secret(), Entity),
   SignB    = permit_hash:sign(Secret, Nonsense),
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

