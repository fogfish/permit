%% @doc
%%   use AWS DynamoDB for key managment 
-module(permit_config_ddb).
-include("permit.hrl").

-export([keypair/0]).

keypair() ->
   case ddb:get(#pubkey{id = {iri, <<"config">>, <<"rsa">>}}) of
      {ok, #pubkey{claims = Claims}} ->
         decode(Claims);
      {error, not_found} ->
         {ok, Public, Secret} = permit_config_rsa:keypair(),
         {ok, _} = ddb:put(#pubkey{
            id = {iri, <<"config">>, <<"rsa">>},
            claims = encode(Public, Secret)
         }),
         {ok, Public, Secret}
   end.

encode(Public, Secret) ->
   #{
      <<"public">> => base64url:encode(erlang:term_to_binary(Public))
   ,  <<"secret">> => base64url:encode(erlang:term_to_binary(Secret))
   }.

decode(#{<<"public">> := Public, <<"secret">> := Secret}) ->
   {ok,
      erlang:binary_to_term(base64url:decode(Public))
   ,  erlang:binary_to_term(base64url:decode(Secret))
   }.