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
      <<"public">> => encode_key('SubjectPublicKeyInfo', Public)
   ,  <<"secret">> => encode_key('RSAPrivateKey', Secret)
   }.

encode_key(Type, Key) ->
   Entry = public_key:pem_entry_encode(Type, Key),
   public_key:pem_encode([Entry]).

decode(#{<<"public">> := Public, <<"secret">> := Secret}) ->
   {ok,
      decode_key(Public)
   ,  decode_key(Secret)
   }.

decode_key(Key) ->
   [Entry] = public_key:pem_decode(Key),
   public_key:pem_entry_decode(Entry).
