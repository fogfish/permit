%% @doc
%%
-module(permit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("permit/src/permit.hrl").
-compile(export_all).

%%
all() ->
   [Test || {Test, NAry} <- ?MODULE:module_info(exports), 
      Test =/= module_info,
      Test =/= init_per_suite,
      Test =/= end_per_suite,
      Test =/= access,
      NAry =:= 1
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

%%%----------------------------------------------------------------------------   
%%%
%%% unit tests
%%%
%%%----------------------------------------------------------------------------   

access(Id) -> {iri, <<"example.com">>, typecast:s(Id)}.
secret() -> <<"secret">>.

%%
create(_Config) ->
   Access = access(create),
   {ok, Token} = permit:create(Access, secret()),
   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(Token).

%%
create_conflict(_Config) ->
   Access = access(conflict),
   {ok,_Token} = permit:create(Access, secret()),
   {error,  _} = permit:create(Access, secret()).

%%
update(_Config) ->
   Access = access(update),
   {ok, TokenA} = permit:create(Access, secret()),
   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(TokenA),

   {ok, TokenB} = permit:update(Access, <<"newsecret">>),
   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access, 
      <<"exp">> := _,
      <<"uid">> := true
   }} = permit:validate(TokenB),
   {error, invalid_signature} = permit:validate(TokenA).

update_notfound(_Config) ->
   {error, not_found} = permit:update(access(not_found), secret()).

%%
lookup(_Config) ->
   Access = access(lookup),
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>},
   {ok, _} = permit:create(Access, secret(), Claims),
   {ok, 
      #pubkey{id = Access, claims = Claims}
   } = permit:lookup(access(lookup)).

%%
lookup_notfound(_Config) ->
   {error, not_found} = permit:lookup(access(not_found)).

%%
revoke(_Config) ->
   Access = access(revoke),
   {ok, Token} = permit:create(Access, secret()),
   {ok, _} = permit:validate(Token),
   {ok, _} = permit:revoke(Access),
   {error, not_found} = permit:validate(Token).   

%%
stateless(_Config) ->
   Access = access(auth),
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok,    _} = permit:create(Access, secret(), Claims),
   {ok, TknA} = permit:stateless(Access, secret(), 3600, Claims),

   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknA).

%%
stateless_invalid_secret(_Config) ->
   Access = access(auth_secret),
   {ok, _} = permit:create(Access, secret()),
   {error, unauthorized} = permit:stateless(Access, <<"unsecret">>, 3600,
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}).

stateless_claims_excalation(_Config) ->
   Access = access(auth_excalation),
   Claims  = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok, TknA} = permit:create(Access, secret(), Claims),
   {error, forbidden} = permit:stateless(Access, secret(), 3600, #{<<"other">> => 1}),
   {error, forbidden} = permit:stateless(Access, secret(), 3600, #{<<"c">> => <<"a">>}),

   {error, forbidden} = permit:stateless(TknA, 3600, #{<<"other">> => 1}),
   {error, forbidden} = permit:stateless(TknA, 3600, #{<<"c">> => <<"a">>}).

revocable(_Config) ->
   Access = access(revoke),
   Claims = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok,    _} = permit:create(Access, secret(), Claims),
   {ok, TknA} = permit:revocable(Access, secret(), 3600, Claims),

   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"rev">> := true,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknA).

revocable_claims_excalation(_Config) ->
   Access = access(revoke_excalation),
   Claims  = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok, TknA} = permit:create(Access, secret(), Claims),
   {error, forbidden} = permit:revocable(Access, secret(), 3600, #{<<"other">> => 1}),
   {error, forbidden} = permit:revocable(Access, secret(), 3600, #{<<"c">> => <<"a">>}),

   {error, forbidden} = permit:revocable(TknA, 3600, #{<<"other">> => 1}),
   {error, forbidden} = permit:revocable(TknA, 3600, #{<<"c">> => <<"a">>}).


%%
pubkey(_Config) ->
   Claims  = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok, _} = permit:create(access(pubkey), secret(), Claims),
   {ok, {Access, Secret}} = permit:pubkey(access(pubkey), #{<<"d">> => false}),

   {ok, Token} = permit:stateless(Access, Secret, 3600, #{<<"d">> => false}),
   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"d">> := false,
      <<"idp">> := <<"example.com">>
   }} = permit:validate(Token).

pubkey_claims_excalation(_Config) ->
   Access = access(pubkey_excalation),
   Claims  = #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false},
   {ok, _} = permit:create(Access, secret(), Claims),
   {error, forbidden} = permit:pubkey(Access, #{<<"other">> => 1}),
   {error, forbidden} = permit:pubkey(Access, #{<<"c">> => <<"a">>}).

%%
exchange(_Config) ->
   Access = access(issue),
   {ok, TknA} = permit:create(Access, secret(), 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {ok, TknB} = permit:stateless(TknA, 600, 
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),
   {ok, #{
      <<"iss">> := <<"permit">>,
      <<"aud">> := <<"permit">>,
      <<"sub">> := Access,
      <<"exp">> := _,
      <<"a">>   := 1,
      <<"b">>   := true,
      <<"c">>   := <<"x">>,
      <<"d">>   := false
   }} = permit:validate(TknB).

%%
exchange_invalid_claims(_Config) ->
   {ok, TknA} = permit:create(access(token_roles), secret(),
      #{<<"a">> => 1, <<"b">> => true, <<"c">> => <<"x">>, <<"d">> => false}),   
   {error, forbidden} = permit:stateless(TknA, 3600, #{<<"e">> => true}).
