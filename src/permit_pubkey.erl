%% @doc
%%    public / private key pair data type 
-module(permit_pubkey).

-compile({parse_transform, category}).
-include("permit.hrl").

-export([
   new/3
,  authenticate/2
]).

%%
%% create new pubkey pair 
-spec new(permit:access(), permit:secret(), permit:roles()) -> datum:either(#pubkey{}).

new({iri, _, _} = Access, Secret, Claims) ->
   Nonce = permit_hash:random(?CONFIG_SALT),
   {ok,
      #pubkey{
         id     = Access
      ,  secret = base64url:encode(permit_hash:sign(Secret, Nonce))
      ,  nonce  = base64url:encode(Nonce)
      ,  claims = Claims
      }
   }.

%%
%% authenticate pubkey pair
-spec authenticate(permit:pubkey(), permit:secret()) -> datum:either(permit:pubkey()). 

authenticate(#pubkey{} = PubKey, Secret) ->
   [either ||
      auth_signature(PubKey, Secret),
      cats:unit(PubKey)
   ].

auth_signature(#pubkey{nonce = Nonce, secret = SignA} = PubKey, Secret) ->
   SignB  = permit_hash:sign(Secret, base64url:decode(Nonce)),
   case permit_hash:eq(base64url:decode(SignA), SignB) of
      true  ->
         {ok, PubKey};
      false ->
         {error, unauthorized}
   end.
