%% @doc
%%
-module(permit_oauth2_SUITE).
-include_lib("common_test/include/ct.hrl").

%% common test
-export([
   all/0,
   groups/0,
   init_per_suite/1,
   end_per_suite/1,
   init_per_group/2,
   end_per_group/2
]).

%% unit tests
-export([
   authenticate/1,
   grant_client_credentials/1,
   grant_owner_credentials/1,
   grant_authorization_code/1
]).

%%%----------------------------------------------------------------------------   
%%%
%%% factory
%%%
%%%----------------------------------------------------------------------------   

all() ->
   [
      {group, oauth2}
   ].

groups() ->
   [
      {oauth2, [parallel], 
         [authenticate, grant_client_credentials, grant_owner_credentials, grant_authorization_code]}
   ].

%%%----------------------------------------------------------------------------   
%%%
%%% init
%%%
%%%----------------------------------------------------------------------------   
init_per_suite(Config) ->
   permit:start(),
   Config.


end_per_suite(_Config) ->
   application:stop(permit),
   ok.

%% 
%%
init_per_group(_, Config) ->
   Config.

end_per_group(_, _Config) ->
   ok.

%%%----------------------------------------------------------------------------   
%%%
%%% unit tests
%%%
%%%----------------------------------------------------------------------------   

authenticate(_Config) ->
   Access  = <<"authenticate">>,
   Secret  = <<"secret">>,
   {ok, _} = permit:create(Access, Secret, [oauth2client]),

   Digest  = base64:encode(<<Access/binary, $:, Secret/binary>>),
   {ok, Access} = permit_oauth2:authenticate([{'Authorization', <<"Basic ", Digest/binary>>}]).


grant_client_credentials(_Config) ->
   %% register client
   Access  = <<"client_credentials">>,
   Secret  = <<"secret">>,
   {ok, _} = permit:create(Access, Secret, [oauth2client]),

   %% request token
   Digest  = base64:encode(<<Access/binary, $:, Secret/binary>>),
   Http    = [{'Authorization', <<"Basic ", Digest/binary>>}],
   Request = <<"grant_type=client_credentials">>,
   {ok, #{
      access_token := Token,
      token_type   := <<"bearer">>,
      expires_in   := 3600
   }} = permit_oauth2:issue_token(Http, Request, 3600),
   
   %% validate token
   {ok, #{
      <<"access">> := Access,
      <<"roles">>  := [<<"oauth2client">>] 
   }} = permit:validate(Token, [oauth2client]).


grant_owner_credentials(_Config) ->
   %% register client
   Access  = <<"clientB_credentials">>,
   Secret  = <<"secret">>,
   {ok, _} = permit:create(Access, Secret, [oauth2client]),

   %% register owner
   Username  = <<"owner_credentials">>,
   Password  = <<"secret">>,
   {ok, _} = permit:create(Username, Password, [test]),

   %% request token
   Digest  = base64:encode(<<Access/binary, $:, Secret/binary>>),
   Http    = [{'Authorization', <<"Basic ", Digest/binary>>}],
   Request = <<"grant_type=password&username=", Username/binary, "&password=", Password/binary>>,
   {ok, #{
      access_token := Token,
      token_type   := <<"bearer">>,
      expires_in   := 3600
   }} = permit_oauth2:issue_token(Http, Request, 3600),
   
   %% validate token
   {ok, #{
      <<"access">> := Username,
      <<"roles">>  := [<<"test">>] 
   }} = permit:validate(Token, [test]).


grant_authorization_code(_Config) ->
   %% register owner
   Access = <<"authorization_code">>,
   Secret = <<"secret">>,
   {ok, Code} = permit:create(Access, Secret, [test]),
   
   Request = <<"grant_type=authorization_code&code=", Code/binary>>,
   {ok, #{
      access_token := Token,
      token_type   := <<"bearer">>,
      expires_in   := 3600
   }} = permit_oauth2:issue_token([], Request, 3600),

   %% validate token
   {ok, #{
      <<"access">> := Access,
      <<"roles">>  := [<<"test">>] 
   }} = permit:validate(Token, [test]).
