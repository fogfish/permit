%% @doc
%%   security token
-module(permit_token).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/2,
   new/3,
   check/2
]).

-define(ALG,   <<"HS256">>).

%%
%% create new token with given ttl and roles
new(PubKey, TTL) ->
   new(PubKey, TTL, lens:get(permit_pubkey:roles(), PubKey)).

new(PubKey, TTL, Roles) ->
   Sub = lens:get(permit_pubkey:access(), PubKey),
   [either ||
      acl(PubKey, TTL, Roles),
      jwt:encode(
         ?ALG,
         #{
            sub => Sub,
            acl => _
         },
         TTL,
         secret()
      )
   ].

acl(PubKey, TTL, Roles) ->
   [either ||
      eitherT(permit_pubkey:acl(PubKey, Roles)),
      build_acl(PubKey, _),
      jwt:encode(?ALG, _, TTL, lens:get(permit_pubkey:secret(), PubKey))
   ].

build_acl(PubKey, List) ->
   Acl0 = maps:from_list([{X, true} || X <- List]),
   Acl1 = Acl0#{
      tji => base64url:encode(uid:encode(uid:g())),
      iss => scalar:s(opts:val(issuer, permit)),
      sub => lens:get(permit_pubkey:access(), PubKey)
   },
   case lens:get(permit_pubkey:master(), PubKey) of
      undefined ->
         {ok, Acl1};
      Master ->
         {ok, Acl1#{master => Master}}
   end.

eitherT([]) -> {error, invalid_roles};
eitherT(Xs) -> {ok, Xs}.


%%
%% check validity of token
check(Token, Secret) ->
   [either ||
      jwt:decode(Token, secret()),
      decode_acl(_, Secret)
   ].

decode_acl(Token, Secret) ->
   [either ||
      fmap(lens:get(lens:map(<<"acl">>), Token)),
      jwt:decode(_, Secret)
   ].


%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

secret() ->
   scalar:s(opts:val(secret, permit)).
