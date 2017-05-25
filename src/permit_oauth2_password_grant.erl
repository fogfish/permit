%% @doc
%%   https://tools.ietf.org/html/rfc6749
%%
%%   4.3 Resource Owner Password Credentials Grant
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
-module(permit_oauth2_password_grant).
-compile({parse_transform, category}).

-export([
   authenticate/1,
   request_access_token/2
]).

%%
%% 2.3. Client Authentication
%% Clients in possession of a client password MAY use the HTTP Basic
%% authentication scheme as defined in [RFC2617] to authenticate with
%% the authorization server.
-spec authenticate(_) -> {ok, _} | {error, _}.

authenticate(HttpHead) ->
   permit_oauth2:http_authenticate(HttpHead).
   
%%
%% 4.3.2.  Access Token Request
-spec request_access_token(_, _) -> {ok, _} | {error, _}. 

request_access_token(_HttpHead, OAuth2Request) ->
   [either ||
      permit_oauth2:request(<<"password">>, OAuth2Request),
      issue_access_token(_),
      permit_oauth2:access_token(_)
   ].

issue_access_token(Request) ->
   Access = lens:get(lens:pair(<<"username">>), Request),
   Secret = lens:get(lens:pair(<<"password">>), Request),
   permit:auth(Access, Secret).


