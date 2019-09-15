%% @doc
%%   security token
-module(permit_token).

-compile({parse_transform, category}).
-include("permit.hrl").

-export([
   stateless/3,
   revocable/3,
   validate/1,
   claims/1
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
revocable(#pubkey{secret = Secret} = PubKey, TTL, Claims) ->
   [either ||
      jwt:encode(?HS256, #{}, TTL, Secret),
      cats:unit(Claims#{<<"rev">> => _}),
      stateless(PubKey, TTL, _)
   ].


%%
%% requires access to secret key of originator
validate(Token) ->
   [either ||
      permit_config:public(),
      jwt:decode(Token, _),
      validate_jwt(_)
   ].

validate_jwt(#{<<"rev">> := Rev} = Claims) ->
   [either ||
      #pubkey{secret = Secret} <- permit_pubkey_db:lookup(subject(Claims)),
      jwt:decode(Rev, Secret),
      cats:unit(Claims#{<<"sub">> => subject(Claims), <<"rev">> => true})
   ];

validate_jwt(Claims) ->
   {ok, Claims#{<<"sub">> => subject(Claims)}}.

subject(#{<<"sub">> := Sub}) ->
   [Suffix, Prefix] = binary:split(Sub, <<$@>>),
   {iri, Prefix, Suffix}.

%%
%%
claims(Token) ->
   [either ||
      permit_config:public(),
      jwt:decode(Token, _),
      check_jwt_claims(_)
   ].

check_jwt_claims(#{<<"rev">> := _} = Claims) ->
   {ok, Claims#{<<"rev">> => true}};
check_jwt_claims(Claims) ->
   {ok, Claims}.


%%
%%
build_acl(PubKey, Claims) ->
   {ok, [identity ||
      tji(Claims),
      iss(_),
      aud(_),
      sub(PubKey, _),
      idp(PubKey, _)
   ]}.

%%
%%
tji(Claims) ->
   Claims#{<<"tji">> => base64url:encode(uid:encode(uid:g()))}.

%%
%%
iss(#{<<"iss">> := _} = Claims) ->
   Claims;
iss(Claims) ->
   Claims#{<<"iss">> => typecast:s(opts:val(issuer, permit))}.

%%
%%
aud(#{<<"aud">> := _} = Claims) ->
   Claims;
aud(Claims) ->
   Claims#{<<"aud">> => typecast:s(opts:val(audience, permit))}.

%%
%%
sub(#pubkey{id = {iri, Prefix, Suffix}}, Claims) ->
   Claims#{<<"sub">> => <<Suffix/binary, $@, Prefix/binary>>}.

%%
%%
idp(#pubkey{id = {iri, Idp, _}}, Claims) ->
   Claims#{<<"idp">> => Idp}.
