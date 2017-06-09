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
   create/2, create/3,
   lookup/2,
   pubkey/1,
   pubkey/2,
   revoke/1,
   auth/2,
   validate/1,
   validate/2
]).

%%
%% data types
-type(access() :: binary()).
-type(secret() :: binary()).
-type(token()  :: binary()).
-type(roles()  :: [binary() | atom()]).

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
%% Create a new pubkey pair, declare unique access and secret identity.
%% The process derives a new pair, stores it and return an identity token.
%%
%% {ok, Token} = permit:create("joe@example.com", "secret").
%%
-spec create(access(), secret()) -> {ok, token()} | {error, _}.
-spec create(access(), secret(), roles()) -> {ok, token()} | {error, _}.

create(Access, Secret) ->
   create(Access, Secret, [uid]).

create(Access, Secret, Roles) ->
   [either ||
      permit_pubkey:new(Access, Secret, Roles),
      permit_keyval:create(_),
      permit_pubkey:authenticate(_, Secret)
   ].

%%
%% Update an existed pubkey pair, use unique access to substitute secret key
%%


%%
%% Lookup an existed pubkey pair, use unique access and secret to prove identity.
%% The process validates a pair against existed one and returns an identity token.  
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
%% revoke pubkey pair associated with access key
-spec revoke(access()) -> ok | {error, _}.

revoke(Access) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_keyval:remove(_)
   ].

%%
%% generate access/secret keys, associate them with master key
-spec pubkey(token()) -> {ok, map()} | {error, any()}.
-spec pubkey(token(), roles()) -> {ok, map()} | {error, any()}.

pubkey(Token) ->
   pubkey(Token, [access]).

pubkey(Token, Roles) ->
   [either ||
      permit_token:check(Token, [uid]),
      pubkey_access_pair(_, Roles)
   ].

pubkey_access_pair(Identity, Roles) ->
   Master = lens:get(permit_pubkey:master(), Identity),
   Access = permit_hash:key(?CONFIG_ACCESS),
   Secret = permit_hash:key(?CONFIG_SECRET),
   [either ||
      permit_pubkey:new(Access, Secret, Roles),
      fmap(lens:put(permit_pubkey:master(), Master, _)),
      permit_keyval:create(_),
      pubkey_access_pair_new(_, Access, Secret)
   ].

pubkey_access_pair_new(_, Access, Secret) ->
   {ok, [$. ||
      lens:put(permit_pubkey:access(), Access, #{}),
      lens:put(permit_pubkey:secret(), Secret, _)
   ]}.


%%-----------------------------------------------------------------------------
%%
%% authorization (oauth)
%%
%%-----------------------------------------------------------------------------

%%
%% Authenticate using unique access and secret to prove identity
%% Returns a token bounded to given roles.
-spec auth(access(), secret()) -> {ok, token()} | {error, _}. 
-spec auth(access(), secret(), roles()) -> {ok, token()} | {error, _}. 

auth(Access, Secret) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_pubkey:authenticate(_, Secret)
   ].
   
auth(Access, Secret, Roles) ->
   [either ||
      permit_keyval:lookup(Access),
      permit_pubkey:authenticate(_, Secret, Roles)
   ].


%%
%% validate access token
-spec validate(token()) -> {ok, map()} | {error, _}.
-spec validate(token(), roles()) -> {ok, map()} | {error, _}.

validate(Token) ->
   permit_token:check(Token, []).

validate(Token, Roles) ->
   permit_token:check(Token, Roles).

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

