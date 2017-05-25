%% @doc
%%   https://tools.ietf.org/html/rfc6749
%%
%%   4.4.  Client Credentials Grant
%%
%% (A)  The client authenticates with the authorization server and
%%      requests an access token from the token endpoint.
%%
%% (B)  The authorization server authenticates the client, and if valid,
%%      issues an access token.
%%
-module(permit_oauth2_credentials_grant).
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
%% 4.4.2. Access Token Request
-spec request_access_token(_, _) -> {ok, _} | {error, _}.

request_access_token(HttpHead, OAuth2Request) ->
   [either ||
      permit_oauth2:request(<<"client_credentials">>, OAuth2Request),
      issue_access_token(HttpHead, _),
      permit_oauth2:access_token(_)
   ].

issue_access_token(HttpHead, _) ->
   case lens:get(lens:pair('Authorization', undefined), HttpHead) of
      undefined ->
         {error, unauthorized};

      <<"Basic ", Digest/binary>> ->
         [Access, Secret] = binary:split(base64:decode(Digest), <<$:>>),
         permit:auth(Access, Secret);

      _ ->
         {error, not_supported}      
   end.
