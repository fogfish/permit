%% @doc
%%   plug-in to fetch public key using jwk, Note plugin required deps to knet 3.x or later
-module(permit_config_jwks).
-compile({parse_transform, category}).

-export([keypair/0]).


keypair() ->
   [either ||
      m_http:once(fetch()),
      jwk:decode(<<"jwt">>, _)
   ].


fetch() ->
   [m_http ||
      _ > "GET " ++ scalar:c(opts:val(jwks, permit)),
      _ > "Accept: application/json",
      _ > "Connection: close",

      _ < 200,
      _ < '*'
   ].