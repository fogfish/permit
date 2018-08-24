%% @doc
%%   configuration plug-in to generate key pairs
-module(permit_config_rsa).
-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-export([keypair/0]).

keypair() ->
   #'RSAPrivateKey'{
      modulus = N, 
      publicExponent = E} = Secret = public_key:generate_key({rsa, 2048, 65537}),
   Public = #'RSAPublicKey'{modulus = N, publicExponent = E},
   {Public, Secret}.
