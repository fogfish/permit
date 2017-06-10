%% @doc
%%   hash utility function
-module(permit_hash).
-include("permit.hrl").

-export([
   random/1
  ,key/1
  ,sign/2
  ,eq/2
]).

%%
%% generate random bytes
random(N) ->
   crypto:strong_rand_bytes(N).

%%
%% generate random N-byte key
key(N) ->
   base64:encode(random(N)).

%% 
%% sign password using given salt
sign(Pass, Salt) ->
   hash:pbkdf2(?CONFIG_PBKDF2_HASH, Pass, Salt, ?CONFIG_PBKDF2_C, ?CONFIG_PBKDF2_DK).

%%
%% time-attack safe compare
eq(HashA, HashB) ->
   lists:foldl(
      fun(X, Y) -> X and Y end,
      true,
      [X =:= Y || 
         {X, Y} <- lists:zip(
            binary_to_list(HashA),
            binary_to_list(HashB)
         )
      ]
   ).
