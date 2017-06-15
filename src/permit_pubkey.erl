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
  ,roles/0

  ,authenticate/2
  ,authenticate/3
  ,authenticate/4
  ,acl/2
]).

%%
%%
-type pubkey() :: map().

%%
%% pubkey attributes 
access() -> lens:map(<<"access">>,  undefined).
secret() -> lens:map(<<"secret">>,  undefined).
master() -> lens:map(<<"master">>,  undefined).
nonce()  -> lens:map(<<"nonce">>,   undefined).
roles()  -> lens:map(<<"roles">>,   undefined).


%%
%% create new pubkey pair 
-spec new(permit:access(), permit:secret(), permit:roles()) -> {ok, pubkey()} | {error, _}.

new(Access, Secret, Roles) ->
   Nonce = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      fmap(#{}),
      lens:put(access(), Access, _),
      lens:put(secret(), base64url:encode(permit_hash:sign(Secret, Nonce)), _),
      lens:put(nonce(), base64url:encode(Nonce), _),
      lens:put(roles(), roles(Roles), _)
   ]}.


%%
%% authenticate pubkey pair and return a token with defined roles
-spec authenticate(pubkey(), permit:secret()) -> {ok, permit:token()} | {error, _}. 

authenticate(PubKey, Secret) ->
   authenticate(PubKey, Secret, ?CONFIG_TTL_ACCESS, lens:get(roles(), PubKey)).

authenticate(PubKey, Secret, TTL) ->
   authenticate(PubKey, Secret, TTL, lens:get(roles(), PubKey)).

authenticate(PubKey, Secret, TTL, Roles) ->
   [either ||
      auth_signature(PubKey, Secret),
      auth_roles(_, Roles),
      permit_token:new(PubKey, TTL, _)      
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

auth_roles(PubKey, Roles) ->
   A = gb_sets:from_list(roles(Roles)),
   B = gb_sets:from_list(lens:get(permit_pubkey:roles(), PubKey)),
   case gb_sets:to_list(gb_sets:intersection(A, B)) of
      [] ->
         {error, scopes};
      Rx ->
         {ok, Rx}
   end.

%%
%% return valid list of roles
-spec acl(pubkey(), permit:roles()) -> permit:roles().

acl(PubKey, Roles) ->
   A = gb_sets:from_list(lens:get(roles(), PubKey)),
   B = gb_sets:from_list(roles(Roles)),
   gb_sets:to_list(gb_sets:intersection(A, B)).

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

roles(Roles) ->
   lists:usort([scalar:s(X) || X <- Roles]).

