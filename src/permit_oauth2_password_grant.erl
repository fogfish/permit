%% @doc
%%   https://tools.ietf.org/html/rfc6749
%%
%%   4.3 Resource Owner Password Credentials Grant
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
-module(permit_oauth2_password_grant).
-include("permit.hrl").

-compile({parse_transform, category}).

-export([
   authenticate/1,
   request_access_token/1
]).

%%
%% 2.3. Client Authentication
%% Clients in possession of a client password MAY use the HTTP Basic
%% authentication scheme as defined in [RFC2617] to authenticate with
%% the authorization server.
-spec authenticate(_) -> {ok, _} | {error, _}.

authenticate(HttpHead) ->
   case lens:get(lens:pair('Authorization', undefined), HttpHead) of
      undefined ->
         {error, unauthorized};

      <<"Basic ", Digest/binary>> ->
         authenticate_basic_digest(Digest);

      _ ->
         {error, not_supported}      
   end.

authenticate_basic_digest(Digest) ->
   [Access, Secret] = binary:split(base64:decode(Digest), <<$:>>),
   [either ||
      permit:auth(Access, Secret),
      permit:validate(_),
      fmap(Access)
   ].
   
%%
%% 4.3.2.  Access Token Request
-spec request_access_token(_) -> {ok, _} | {error, _}. 

request_access_token(OAuth2Request) ->
   [either ||
      fmap(binary:split(OAuth2Request, <<$&>>, [trim, global])),
      fmap(lists:map(fun(X) -> erlang:list_to_tuple(binary:split(X, <<$=>>)) end, _)),
      validate_token_request(_),
      issue_access_token(_),
      oauth2_access_token(_)
   ].

validate_token_request(Request) ->
   case lens:get(lens:pair(<<"grant_type">>), Request) of
      <<"password">> ->
         {ok, Request};
      _ ->
         {error, invalid_grant}
   end.

issue_access_token(Request) ->
   Access = lens:get(lens:pair(<<"username">>), Request),
   Secret = lens:get(lens:pair(<<"password">>), Request),
   permit:auth(Access, Secret).

oauth2_access_token(Token) ->
   #{
      access_token => Token,
      token_type   => "bearer",
      expires_in   => ?CONFIG_TTL_ACCESS
   }.
