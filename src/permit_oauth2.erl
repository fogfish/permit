%% @doc
%%   oauth2 primitives
-module(permit_oauth2).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   decode/1,
   authenticate/1,
   issue_token/3
   % request/2,
   % access_token/1
]).

%%
%% decodes oauth2 request
%% parse application/x-www-form-urlencoded oauth2 request as pairs
-spec decode(_) -> {ok, _} | {error, _}.  

decode(Request) ->
   [$. ||
      binary:split(scalar:s(Request), <<$&>>, [trim, global]),
      lists:map(fun as_pair/1, _)
   ].

as_pair(Pair) ->
   erlang:list_to_tuple(
      [uri:unescape(X) || X <- binary:split(Pair, <<$=>>)]
   ).


%%
%% 2.3. Client Authentication
%%   Clients in possession of a client password MAY use the HTTP Basic
%%   authentication scheme as defined in [RFC2617] to authenticate with
%%   the authorization server.
%% @see 
%%   * https://tools.ietf.org/html/rfc6749
%%   * https://tools.ietf.org/html/rfc2617
%%
-spec authenticate(_) -> {ok, _} | {error, _}.

authenticate(HttpHead) ->
   [either ||
      client_identity(HttpHead),
      authenticate_client(_)
   ].

authenticate_client([Access, Secret]) ->
   [either ||
      permit:auth(Access, Secret),
      fmap(Access)
   ].

%%
%% issue token, exchange authentication grant for the token
issue_token(HttpHead, Request, TTL) ->
   Pairs = decode(Request),
   Grant = lens:get(lens:pair(<<"grant_type">>), Pairs),
   issue_token(Grant, HttpHead, Pairs, TTL).

%%
%% 
issue_token(<<"authorization_code">>, _HttpHead, Request, TTL) ->
   [either ||
      fmap(lens:get(lens:pair(<<"code">>), Request)),
      permit:token(_, TTL),
      access_token(_, TTL)
   ];

%%
%% 4.3 Resource Owner Password Credentials Grant
%%
%% (A)  The resource owner provides the client with its username and
%%      password.
%%
%% (B)  The client requests an access token from the authorization
%%      server's token endpoint by including the credentials received
%%      from the resource owner.  When making the request, the client
%%      authenticates with the authorization server.
%%
%% (C)  The authorization server authenticates the client and validates
%%      the resource owner credentials, and if valid, issues an access
%%      token.
%%
issue_token(<<"password">>, HttpHead, Request, TTL) ->
   [either ||
      client_identity(HttpHead),
      fun([Access, Secret]) -> permit:auth(Access, Secret) end,
      owner_identity(Request),
      fun([Access, Secret]) -> permit:auth(Access, Secret) end,
      access_token(_, TTL)   
   ];

%%
%% 4.4.  Client Credentials Grant
%%
%% (A)  The client authenticates with the authorization server and
%%      requests an access token from the token endpoint.
%%
%% (B)  The authorization server authenticates the client, and if valid,
%%      issues an access token.
%%
issue_token(<<"client_credentials">>, HttpHead, _Request, TTL) ->
   [either ||
      client_identity(HttpHead),
      fun([Access, Secret]) -> permit:auth(Access, Secret) end,
      access_token(_, TTL)
   ];

issue_token(_, _, _, _) ->
   {error, invalid_grant}.


%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
%%
client_identity(HttpHead) ->
   case lens:get(lens:pair('Authorization', undefined), HttpHead) of
      undefined ->
         {error, unauthorized};

      <<"Basic ", Digest/binary>> ->
         {ok, binary:split(base64:decode(Digest), <<$:>>)};

      _ ->
         {error, not_supported}      
   end.     

%%
%%
owner_identity(Request) ->
   Access = lens:get(lens:pair(<<"username">>), Request),
   Secret = lens:get(lens:pair(<<"password">>), Request),
   {ok, [Access, Secret]}.


%%
%% return OAuth2 access token, uses permit token as input
access_token(Token, TTL) ->
   {ok, #{
      access_token => Token,
      token_type   => <<"bearer">>,
      expires_in   => TTL
   }}.

