%% @doc
%%   oauth2 primitives
-module(permit_oauth2).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   decode/1,
   authenticate/1,
   issue_token/3
]).

%%
%% decodes oauth2 request
%% parse application/x-www-form-urlencoded oauth2 request as pairs
-spec decode(_) -> {ok, _} | {error, _}.  

decode(Request) ->
   [$. ||
      binary:split(scalar:s(Request), <<$&>>, [trim, global]),
      lists:map(fun as_pair/1, _),
      maps:from_list(_)
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
      permit:auth(Access, Secret, 3600, [oauth2client]),
      fmap(Access)
   ].

%%
%% issue token, exchange authentication grant for the token
issue_token(HttpHead, Request, TTL) ->
   #{<<"grant_type">> := Grant} = Req = decode(Request),
   issue_token(Grant, HttpHead, Req, TTL).

%%
%% 
issue_token(<<"authorization_code">>, _HttpHead, #{<<"code">> := Code}, TTL) ->
   [either ||
      permit:validate(Code),
      fmap(lens:get(lens:map(<<"sub">>), _)),
      permit:issue(_, TTL),
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
issue_token(<<"password">>, _HttpHead, #{<<"username">> := Access, <<"password">> := Secret}, TTL) ->
   [either ||
      permit:auth(Access, Secret, TTL),
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
      fun([Access, Secret]) -> permit:auth(Access, Secret, TTL, [oauth2client]) end,
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
         {error, undefined};

      <<"Basic ", Digest/binary>> ->
         {ok, binary:split(base64:decode(Digest), <<$:>>)};

      _ ->
         {error, not_supported}      
   end.     

%%
%% return OAuth2 access token, uses permit token as input
access_token(Token, TTL) ->
   {ok, #{
      access_token => Token,
      token_type   => <<"bearer">>,
      expires_in   => TTL
   }}.

