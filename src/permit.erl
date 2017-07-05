%% @doc 
%%   https://crackstation.net/hashing-security.htm
%%   1. hash and salt password using sha256 and 256-bit salt
%%   2. use PBKDF2 to stretch key
%%   3. encrypt hash using AES
%%
%% @todo
%%   * associate user data with cert (root + pubkey e.g. first/last names, device id, etc)
%%   * associate token scope with cert
%%   * management interface to revoke key
-module(permit).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([start/0, ephemeral/0]).
-export([
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
   validate/1
]).
-export_type([access/0, secret/0, token/0, claims/0, pubkey/0]).

%%
%% data types
-type access()   :: binary().
-type secret()   :: binary().
-type token()    :: binary().
-type claims()   :: #{binary() => _}.
-type pubkey()   :: #{binary() => _}.
-type identity() :: #{binary() => _}.

%%
%%
start() ->
   applib:boot(?MODULE, code:where_is_file("app.config")).

%%
%% enable ephemeral mode for permit
ephemeral() ->
   Spec = [
      'read-through',
      {factory, temporary},
      {entity,  {permit_pubkey_io, start_link, [undefined]}}
   ],
   supervisor:start_child(permit_sup, 
      {pts,  {pts, start_link, [permit, Spec]}, permanent, 5000, supervisor, dynamic}
   ).


%%
%% Create a new pubkey pair, declare unique access and secret identity.
%% The process derives a new pair, stores it and return an identity token.
%%
%% {ok, Token} = permit:create("joe@example.com", "secret").
%%
-spec create(access(), secret()) -> {ok, token()} | {error, _}.
-spec create(access(), secret(), claims()) -> {ok, token()} | {error, _}.

create(Access, Secret) ->
   create(Access, Secret, default_claims()).

create(Access, Secret, Claims)
 when is_binary(Access), is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Claims),
      permit_pubkey_io:create(_),
      permit_pubkey:authenticate(_, Secret),
      permit_token:revocable(_, ?CONFIG_TTL_ACCESS, Claims)
   ];

create(Access, Secret, Roles) ->
   create(scalar:s(Access), scalar:s(Secret), Roles).
 
%%  
%% Update an existed pubkey pair, use unique access to substitute secret key
%% all allocated tokens becomes invalid
-spec update(access(), secret()) -> {ok, token()} | {error, _}.
-spec update(access(), secret(), claims()) -> {ok, token()} | {error, _}.

update(Access, Secret) ->
   update(Access, Secret, default_claims()).

update(Access, Secret, Claims)
 when is_binary(Access), is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Claims),
      permit_pubkey_io:update(_),
      permit_pubkey:authenticate(_, Secret),
      permit_token:revocable(_, ?CONFIG_TTL_ACCESS, Claims)
   ];

update(Access, Secret, Claims) ->
   update(scalar:s(Access), scalar:s(Secret), Claims).

%%
%% Lookup an existed pubkey pair, use unique access and secret to prove identity.
%% The process validates a pair against existed one and returns an identity token.  
%%
%% {ok, Token} = permit:signup("joe@example.com", "secret").
%%
-spec lookup(access()) -> {ok, pubkey()} | {error, any()}.

lookup(Access) ->
   permit_pubkey_io:lookup(scalar:s(Access)).

%%
%% revoke pubkey pair associated with access key
-spec revoke(access()) -> {ok, pubkey()} | {error, _}.

revoke(Access) ->
   [either ||
      permit_pubkey_io:lookup(scalar:s(Access)),
      permit_pubkey_io:remove(_)
   ].


%%
%% derive a new pubkey pair from master access key
-spec pubkey(access()) -> {ok, identity()} | {error, _}.
-spec pubkey(access(), claims()) -> {ok, identity()} | {error, _}.

pubkey(Master) ->
   pubkey(Master, default_claims()).

pubkey(Master, Claims) ->
   Access = permit_hash:key(?CONFIG_ACCESS),
   Secret = permit_hash:key(?CONFIG_SECRET),
   [either ||
      permit:lookup(Master),
      permit_pubkey:new(Access, Secret, Claims),
      fmap(lens:put(permit_pubkey:master(), scalar:s(Master), _)),
      permit_pubkey_io:create(_),
      pubkey_access_pair_new(_, Access, Secret)
   ].

pubkey_access_pair_new(_PubKey, Access, Secret) ->
   {ok, [$. ||
      fmap(#{}),
      lens:put(permit_pubkey:access(), Access, _),
      lens:put(permit_pubkey:secret(), Secret, _)
   ]}.

%%
%% authenticate the identity (access/secret) and 
%% return a stateless token with given ttl and claims
-spec stateless(access(), secret(), timeout(), claims()) -> {ok, token()} | {error, _}.
-spec stateless(token(), timeout(), claims()) -> {ok, token()} | {error, _}.

stateless(Access, Secret, TTL, Claims) ->
   [either ||
      permit_pubkey_io:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, Secret),
      permit_token:stateless(_, TTL, Claims)
   ].

stateless(Token, TTL, Claims) ->
   [either ||
      permit:validate(Token),
      category:maybeT(unauthorized,
         lens:get(lens:map(<<"sub">>), _)
      ),
      permit_pubkey_io:lookup(_),
      permit_token:stateless(_, TTL, Claims)
   ].

%%
%% authenticate the identity (access/secret) and 
%% return a revocable token with given ttl and claims
-spec revocable(access(), secret(), timeout(), claims()) -> {ok, token()} | {error, _}.
-spec revocable(token(), timeout(), claims()) -> {ok, token()} | {error, _}.

revocable(Access, Secret, TTL, Claims) ->
   [either ||
      permit_pubkey_io:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, Secret),
      permit_token:revocable(_, TTL, Claims)
   ].

revocable(Token, TTL, Claims) ->
   [either ||
      permit:validate(Token),
      category:maybeT(unauthorized,
         lens:get(lens:map(<<"sub">>), _)
      ),
      permit_pubkey_io:lookup(_),
      permit_token:revocable(_, TTL, Claims)
   ].

   
%%
%% validate access token
-spec validate(token()) -> {ok, map()} | {error, _}.

validate(Token) ->
   permit_token:validate(Token).

%%
%%
default_claims() ->
   [$. ||
      opts:val(roles, permit),
      scalar:s(_),
      binary:split(_, <<$ >>, [trim, global]),
      lists:map(fun(X) -> {X, true} end, _),
      maps:from_list(_)
   ].

