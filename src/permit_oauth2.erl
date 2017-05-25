%% @doc
%%   OAuth2 primitives and utilities
-module(permit_oauth2).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   http_authenticate/1,  
   request/2,
   access_token/1
]).

%%
%% https://tools.ietf.org/html/rfc2617
-spec http_authenticate(_) -> {ok, _} | {error, _}.

http_authenticate(HttpHead) ->
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
%%
request(Type, OAuth2Request) ->
   [either ||
      fmap(binary:split(OAuth2Request, <<$&>>, [trim, global])),
      fmap(lists:map(fun(X) -> erlang:list_to_tuple(binary:split(X, <<$=>>)) end, _)),
      validate_grant_type(Type, _)
   ].

validate_grant_type(Type, Request) ->
   case lens:get(lens:pair(<<"grant_type">>), Request) of
      Type ->
         {ok, Request};
      _ ->
         {error, invalid_grant}
   end.

%%
%% return OAuth2 access token, uses permit token as input
access_token(Token) ->
   #{
      access_token => Token,
      token_type   => "bearer",
      expires_in   => ?CONFIG_TTL_ACCESS
   }.

