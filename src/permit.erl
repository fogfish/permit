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
   lookup/2,
   pubkey/1,
   pubkey/2,
   revoke/1,
   auth/2,
   validate/1,
   validate/2,
   validate/3
]).

%%
%% data types
-type(access() :: binary()).
-type(secret() :: binary()).
-type(token()  :: binary()).

%%
%%
start() ->
   applib:boot(?MODULE, code:where_is_file("app.config")).

%%-----------------------------------------------------------------------------
%%
%% key management
%%
%%-----------------------------------------------------------------------------

%%
%% Create a new account, declare unique access and secret identity.
%% The process derives a new certificate, stores it and return an identity token.
%%
%% {ok, Token} = permit:signup("joe@example.com", "secret").
%%
-spec create(access(), secret()) -> {ok, token()} | {error, _}.

create(Access, Secret) ->
   [either ||
      permit_pubkey:new(Access, Secret, [uid]),
      permit_keyval:create(_),
      permit_pubkey:authenticate(_, Secret)
   ].

%%
%% Lookup an existed account, use unique access and secret to prove identity.
%% The process validates a certificate against existed one and returns an identity token.  
%%
%% {ok, Token} = permit:signup("joe@example.com", "secret").
%%
-spec lookup(access(), secret()) -> {ok, token()} | {error, any()}.

lookup(Access, Secret) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_pubkey:authenticate(_, Secret)
   ].

%%
%% generate access/secret keys, associate them with master key
-spec pubkey(token()) -> {ok, map()} | {error, any()}.
-spec pubkey(token(), [_]) -> {ok, map()} | {error, any()}.

pubkey(Token) ->
   pubkey(Token, [access]).

pubkey(Token, Scope) ->
   [either ||
      permit_token:check(?CONFIG_TTL_MASTER, uid, Token),
      pubkey_access_pair(_, Scope)
   ].

pubkey_access_pair(Master, Scope) ->
   Access = permit_hash:key(?CONFIG_ACCESS),
   Secret = permit_hash:key(?CONFIG_SECRET),
   [either ||
      permit_pubkey:new(Access, Secret, Scope),
      fmap(lens:put(permit_pubkey:master(), Master, _)),
      permit_keyval:create(_),
      pubkey_access_pair_new(_, Access, Secret)
   ].

pubkey_access_pair_new(_, Access, Secret) ->
   {ok, [$. ||
      lens:put(permit_pubkey:access(), Access, #{}),
      lens:put(permit_pubkey:secret(), Secret, _)
   ]}.

%%
%% revoke certificate(s) associated with access key
-spec revoke(access()) -> ok | {error, _}.

revoke(Access) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_keyval:remove(_)
   ].      

%%-----------------------------------------------------------------------------
%%
%% authorization (oauth)
%%
%%-----------------------------------------------------------------------------

%%
%% Authenticate use unique access and secret to prove identity
%% Returns a restricted token.
-spec auth(access(), secret()) -> {ok, token()} | {error, _}. 

auth(Access, Secret) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_pubkey:authenticate(_, Secret)
   ].

%%
%% validate access token
-spec validate(token()) -> {ok, access()} | {error, unauthorized}.
-spec validate(_, token()) -> {ok, access()} | {error, unauthorized}.
-spec validate(_, integer(), token()) -> {ok, access()} | {error, unauthorized}.

validate(Token) ->
   validate(access, Token).

validate(Scope, Token) ->
   validate(Scope, ?CONFIG_TTL_ACCESS, Token).

validate(Scope, TTL, Token) ->
   permit_token:check(TTL, Scope, Token).

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

