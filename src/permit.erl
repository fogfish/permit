%% @doc 
%%   https://crackstation.net/hashing-security.htm
%%   1. hash and salt password using sha256 and 256-bit salt
%%   2. use PBKDF2 to stretch key
%%   3. encrypt hash using AES
-module(permit).

-compile({parse_transform, category}).
-include("permit.hrl").

-export([start/0]).
-export([
   public/0,
   create/2, 
   create/3,
   update/2,
   update/3,
   lookup/1,
   pubkey/1,
   pubkey/2,
   revoke/1,
   stateless/3,
   stateless/4,
   revocable/3,
   revocable/4,
   validate/1,
   claims/1,
   include/2,
   exclude/2,
   equals/2,
   default_claims/0
]).
-export_type([access/0, secret/0, token/0, claims/0]).

%%
%% data types
-type access()   :: {iri, binary(), binary()}.
-type secret()   :: binary().
-type token()    :: binary().
-type claims()   :: #{binary() => _}.
-type identity() :: {access(), secret()}.

%%
%%
start() ->
   applib:boot(?MODULE, code:where_is_file("app.config")).

%%
%% return public key
public() ->
   permit_config:public().

%%
%% Create a new pubkey pair, declare unique access and secret identity.
%% The process derives a new pair, stores it and return an identity token.
%%
%% {ok, Token} = permit:create({iri, "com.example", "joe"}, "secret").
%%
-spec create(access(), secret()) -> datum:either(token()).
-spec create(access(), secret(), claims()) -> datum:either(token()).

create(Access, Secret) ->
   create(Access, Secret, default_claims()).

create({iri, _, _} = Access, Secret, Claims)
 when is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Claims),
      permit_pubkey_db:create(_),
      permit_pubkey:authenticate(_, Secret),
      permit_token:revocable(_, ?CONFIG_TTL_ACCESS, Claims)
   ].

%%  
%% Update an existed pubkey pair, use unique access to substitute secret key
%% all allocated tokens becomes invalid
-spec update(access(), secret()) -> datum:either(token()).
-spec update(access(), secret(), claims()) -> datum:either(token()).

update(Access, Secret) ->
   update(Access, Secret, default_claims()).

update({iri, _, _} = Access, Secret, Claims)
 when is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Claims),
      permit_pubkey_db:update(_),
      permit_pubkey:authenticate(_, Secret),
      permit_token:revocable(_, ?CONFIG_TTL_ACCESS, Claims)
   ].

%%
%% Lookup an existed pubkey pair
-spec lookup(access()) -> datum:either(#pubkey{}).

lookup({iri, _, _} = Access) ->
   permit_pubkey_db:lookup(Access).

%%
%% revoke pubkey pair associated with access key
-spec revoke(access()) -> datum:either(#pubkey{}).

revoke({iri, _, _} = Access) ->
   [either ||
      permit_pubkey_db:lookup(Access),
      permit_pubkey_db:remove(_)
   ].


%%
%% derive a new pubkey pair from master access key
-spec pubkey(access()) -> datum:either(identity()).
-spec pubkey(access(), claims()) -> datum:either(identity()).

pubkey(Master) ->
   pubkey(Master, default_claims()).

pubkey({iri, Prefix, _} = Master, Claims) ->
   Access = {iri, Prefix, permit_hash:key(?CONFIG_ACCESS)},
   Secret = permit_hash:key(?CONFIG_SECRET),
   [either ||
      #pubkey{
         claims = Required
      } <- permit:lookup(Master),
      include_it(Required, Claims),
      permit_pubkey:new(Access, Secret, Claims),
      permit_pubkey_db:create(_),
      cats:unit({Access, Secret})
   ].


%%
%% authenticate the identity (access/secret) and 
%% return a stateless token with given ttl and claims
-spec stateless(access(), secret(), timeout(), claims()) -> datum:either(token()).
-spec stateless(token(), timeout(), claims()) -> datum:either(token()).

stateless({iri, _, _} = Access, Secret, TTL, Claims) ->
   [either ||
      permit_pubkey_db:lookup(Access),
      #pubkey{
         claims = Required
      } = PubKey <- permit_pubkey:authenticate(_, Secret),
      include_it(Required, Claims),
      permit_token:stateless(PubKey, TTL, Claims)
   ].

stateless(Token, TTL, Claims) ->
   [either ||
      permit:validate(Token),
      cats:optionT(unauthorized,
         lens:get(lens:at(<<"sub">>), _)
      ),
      #pubkey{
         claims = Required
      } = PubKey <- permit_pubkey_db:lookup(_),
      include_it(Required, Claims),
      permit_token:stateless(PubKey, TTL, Claims)
   ].

%%
%% authenticate the identity (access/secret) and 
%% return a revocable token with given ttl and claims
-spec revocable(access(), secret(), timeout(), claims()) -> datum:either(token()).
-spec revocable(token(), timeout(), claims()) -> datum:either(token()).

revocable({iri, _, _} = Access, Secret, TTL, Claims) ->
   [either ||
      permit_pubkey_db:lookup(Access),
      #pubkey{
         claims = Required
      } = PubKey <- permit_pubkey:authenticate(_, Secret),
      include_it(Required, Claims),
      permit_token:revocable(PubKey, TTL, Claims)
   ].

revocable(Token, TTL, Claims) ->
   [either ||
      permit:validate(Token),
      cats:optionT(unauthorized,
         lens:get(lens:at(<<"sub">>), _)
      ),
      #pubkey{
         claims = Required
      } = PubKey <- permit_pubkey_db:lookup(_),
      include_it(Required, Claims),
      permit_token:revocable(PubKey, TTL, Claims)
   ].

   
%%
%% Deep validation of access token, checks if revocation flag is valid
%% requires access to secret key 
-spec validate(token()) -> datum:either(claims()).

validate(Token) ->
   permit_token:validate(Token).


%%
%% validate access token, skips revocation flag
%% uses stateless methods of validation 
-spec claims(token()) -> datum:either(claims()).

claims(Token) ->
   permit_token:claims(Token).


%%
%% token includes claims, required claims are subset of origin
-spec include(token(), claims()) -> datum:either(claims()).

include(Token, Required)
 when is_binary(Token) ->
   [either ||
      permit_token:claims(Token),
      include_it(_, Required)
   ];

include(#pubkey{claims = Claims}, Required) ->
   include_it(Claims, Required).

include_it(Claims, Required)
 when is_map(Claims) andalso is_map(Required) ->
   case maps:with(maps:keys(Required), Claims) of
      Required ->
         {ok, Claims};
      _ ->
         {error, forbidden}
   end.

%%
%% token exclude claims
-spec exclude(token(), claims()) -> datum:either(claims()).

exclude(Token, Required)
 when is_binary(Token) ->
   [either ||
      permit_token:claims(Token),
      exclude_it(_, Required)
   ];

exclude(#pubkey{claims = Claims}, Required) ->
   exclude_it(Claims, Required).

exclude_it(Claims, Required)
 when is_map(Claims) andalso is_map(Required) ->
   case maps:with(maps:keys(Required), Claims) of
      Required ->
         {error, forbidden};
      _ ->
         {ok, Claims}
   end.

%%
%% claims are exactly equals to token claims
%% Note: it skips a check of exp, iss, sub, tji
-spec equals(token(), claims()) -> datum:either(claims()).

equals(Token, Required)
 when is_binary(Token) ->
   [either ||
      permit_token:claims(Token),
      equals_match(_, Required)
   ];

equals(#pubkey{claims = Claims}, Required) ->
   equals_match(Claims, Required).

equals_match(Claims, Required)
 when is_map(Claims) andalso is_map(Required) ->
   PureClaims = maps:without(
      [<<"aud">>, <<"exp">>, <<"iss">>, <<"sub">>, <<"tji">>, <<"idp">>,<<"rev">>],
      Claims
   ),
   Keys = maps:keys(PureClaims),
   case maps:keys(Required) of
      Keys ->
         include_it(Claims, Required);
      _ ->
         {error, forbidden}
   end.

%%
%%
default_claims() ->
   [identity ||
      permit_config:claims(),
      binary:split(_, <<$&>>, [trim, global]),
      lists:map(fun(X) -> [Key, Val] = binary:split(X, <<$=>>), {Key, scalar:decode(Val)} end, _),
      maps:from_list(_)
   ].

