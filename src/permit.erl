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

-export([start/0]).
-export([
   create/2, 
   create/3,
   update/2,
   update/3,
   lookup/2,
   pubkey/1,
   pubkey/2,
   revoke/1,
   auth/2, 
   auth/3, 
   auth/4,
   code/2,
   token/1,
   token/2,
   token/3,
   validate/1,
   validate/2
]).
-export_type([access/0, secret/0, token/0, roles/0]).

%%
%% data types
-type access()   :: binary().
-type secret()   :: binary().
-type token()    :: binary().
-type roles()    :: [binary() | atom()].

%%
%%
start() ->
   applib:boot(?MODULE, []).

%%
%% Create a new pubkey pair, declare unique access and secret identity.
%% The process derives a new pair, stores it and return an identity token.
%%
%% {ok, Token} = permit:create("joe@example.com", "secret").
%%
-spec create(access(), secret()) -> {ok, token()} | {error, _}.
-spec create(access(), secret(), roles()) -> {ok, token()} | {error, _}.

create(Access, Secret) ->
   create(Access, Secret, [uid]).

create(Access, Secret, Roles)
 when is_binary(Access), is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Roles),
      permit_keyval:create(_),
      permit_pubkey:authenticate(_, Secret)
   ];

create(Access, Secret, Roles) ->
   create(scalar:s(Access), scalar:s(Secret), Roles).

%%
%% Update an existed pubkey pair, use unique access to substitute secret key
%% all allocated tokens becomes invalid
-spec update(access(), secret()) -> {ok, token()} | {error, _}.
-spec update(access(), secret(), roles()) -> {ok, token()} | {error, _}.

update(Access, Secret) ->
   update(Access, Secret, [uid]).

update(Access, Secret, Roles)
 when is_binary(Access), is_binary(Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, Roles),
      permit_keyval:update(_),
      permit_pubkey:authenticate(_, Secret)
   ];

update(Access, Secret, Roles) ->
   update(scalar:s(Access), scalar:s(Secret), Roles).

%%
%% Lookup an existed pubkey pair, use unique access and secret to prove identity.
%% The process validates a pair against existed one and returns an identity token.  
%%
%% {ok, Token} = permit:signup("joe@example.com", "secret").
%%
-spec lookup(access(), secret()) -> {ok, token()} | {error, any()}.

lookup(Access, Secret) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, scalar:s(Secret))
   ].

%%
%% revoke pubkey pair associated with access key
-spec revoke(access()) -> {ok, _} | {error, _}.

revoke(Access) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      permit_keyval:remove(_)
   ].


%%
%% derive a new pubkey pair from master key
-spec pubkey(token()) -> {ok, map()} | {error, any()}.
-spec pubkey(token(), roles()) -> {ok, map()} | {error, any()}.

pubkey(Token) ->
   pubkey(Token, [access]).

pubkey(Token, Roles) ->
   [either ||
      permit:validate(Token),
      pubkey_access_pair(_, Roles)
   ].

pubkey_access_pair(Identity, Roles) ->
   Master = lens:get(permit_pubkey:access(), Identity),
   Access = permit_hash:key(?CONFIG_ACCESS),
   Secret = permit_hash:key(?CONFIG_SECRET),
   [either ||
      permit_pubkey:new(Access, Secret, Roles),
      fmap(lens:put(permit_pubkey:master(), Master, _)),
      permit_keyval:create(_),
      pubkey_access_pair_new(_, Access, Secret)
   ].

pubkey_access_pair_new(_PubKey, Access, Secret) ->
   {ok, [$. ||
      lens:put(permit_pubkey:access(), Access, #{}),
      lens:put(permit_pubkey:secret(), Secret, _)
   ]}.

%%
%% Authenticate using unique access and secret to prove identity
%% Returns a token bounded to given roles.
-spec auth(access(), secret()) -> {ok, token()} | {error, _}. 
-spec auth(access(), secret(), timeout()) -> {ok, token()} | {error, _}. 
-spec auth(access(), secret(), timeout(), roles()) -> {ok, token()} | {error, _}. 

auth(Access, Secret) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, Secret)
   ].

auth(Access, Secret, TTL) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, Secret, TTL)
   ].
   
auth(Access, Secret, TTL, Roles) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      permit_pubkey:authenticate(_, Secret, TTL, Roles)
   ].

%%
%% create access token for password-less identity
-spec code(access(), timeout()) -> {ok, token()} | {error, _}. 

code(Access, TTL) ->
   [either ||
      permit_keyval:lookup(scalar:s(Access)),
      token_create_new(_, TTL)
   ].

%%
%% derive a new token from existed one
-spec token(token()) -> {ok, token()} | {error, _}.
-spec token(token(), timeout()) -> {ok, token()} | {error, _}.
-spec token(token(), timeout(), roles()) -> {ok, token()} | {error, _}.

token(Token) ->
   token(Token, ?CONFIG_TTL_ACCESS).

token(Token, TTL) ->
   token(Token, TTL, []).

token(Token, TTL, Roles) ->
   [either ||
      validate(Token, Roles),
      token_create_new(_, TTL)
   ].

token_create_new(Identity, TTL) ->
   Access = lens:get(permit_pubkey:access(), Identity),
   Roles  = lens:get(permit_pubkey:roles(), Identity),
   [either ||
      permit_keyval:lookup(Access),
      permit_token:new(_, TTL, Roles),
      permit_token:encode(_)
   ]. 
   
%%
%% validate access token
-spec validate(token()) -> {ok, map()} | {error, _}.
-spec validate(token(), roles()) -> {ok, map()} | {error, _}.

validate(Token) ->
   validate(Token, []).

validate(Token, Roles) ->
   [either ||
      permit_token:decode(Token),
      fmap(lens:get(permit_token:access(), _)),
      permit_keyval:lookup(_),
      fmap(lens:get(permit_pubkey:secret(), _)),
      permit_token:check(Token, _, Roles)
   ].
