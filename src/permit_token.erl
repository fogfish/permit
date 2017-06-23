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
   new(PubKey, TTL, permit_pubkey:claims(PubKey)).

new(PubKey, TTL, Claims) ->
   Sub = lens:get(permit_pubkey:access(), PubKey),
   [either ||
      acl(PubKey, TTL, Claims),
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

acl(PubKey, TTL, Claims) ->
   [either ||
      permit_pubkey:acl(PubKey, Claims),
      build_acl(PubKey, _),
      jwt:encode(?ALG, _, TTL, lens:get(permit_pubkey:secret(), PubKey))
   ].

build_acl(_PubKey, Claims)
 when map_size(Claims) =:= 0 ->
   {error, unauthorized};

build_acl(PubKey, Claims) ->
   Acl = Claims#{
      tji => base64url:encode(uid:encode(uid:g())),
      iss => scalar:s(opts:val(issuer, permit)),
      sub => lens:get(permit_pubkey:access(), PubKey)
   },
   case lens:get(permit_pubkey:master(), PubKey) of
      undefined ->
         {ok, Acl};
      Master ->
         {ok, Acl#{master => Master}}
   end.

% eitherT([]) -> {error, invalid_roles};
% eitherT(Xs) -> {ok, Xs}.


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
