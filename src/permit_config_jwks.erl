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
      _ > "GET " ++ permit_config:jwks(),
      _ > "Accept: application/json",
      _ > "Connection: keep-alive",

      _ < 200,
      _ < '*'
   ].