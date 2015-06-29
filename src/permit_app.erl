-module(permit_app).
-behaviour(application).

-export([
   start/2
  ,stop/1
]).

%%
%%
start(_Type, _Args) ->
   permit_sup:start_link().

%%
%%
stop(_State) ->
   ok.
