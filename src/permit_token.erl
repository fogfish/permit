%% @doc
%%   security token
-module(permit_token).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   stateless/3,
   revocable/3,
   validate/1
]).

-define(RS256,   <<"RS256">>).
-define(HS256,   <<"HS256">>).

%%
%% create new stateless token with given ttl and claims
stateless(PubKey, TTL, Claims) ->
   [either ||
      build_acl(PubKey, Claims),
      stateless(TTL, _)
   ].

stateless(TTL, Claims) ->
   [either ||
      permit_config:secret(),
      jwt:encode(?RS256, Claims, TTL, _)
   ].

%%
%% create new revocable token with given ttl and claims
revocable(PubKey, TTL, Claims) ->
   [either ||
      jwt:encode(?HS256, #{}, TTL, lens:get(permit_pubkey:secret(), PubKey)),
      fmap(Claims#{<<"rev">> => _}),
      stateless(PubKey, TTL, _)
   ].


%%
%%
validate(Token) ->
   [either ||
      permit_config:public(),
      jwt:decode(Token, _),
      validate_jwt(_)
   ].

validate_jwt(#{<<"rev">> := Rev, <<"sub">> := Sub} = Claims) ->
   [either ||
      permit_pubkey_io:lookup(Sub),
      fmap(lens:get(permit_pubkey:secret(), _)),
      jwt:decode(Rev, _),
      fmap(Claims#{<<"rev">> => true})
   ];

validate_jwt(Claims) ->
   {ok, Claims}.


%%
%%
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
