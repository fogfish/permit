-module(permit_app).
-behaviour(application).

-export([
   start/2
  ,stop/1
  ,uri_protocol/2
]).

%%
%%
start(_Type, _Args) ->
   permit_sup:start_link().

%%
%%
stop(_State) ->
   ok.

%%
%%
uri_protocol(permit, mem) -> permit_pubkey_io.