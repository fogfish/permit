%% @doc
%%   key / value interface to manage pubkey pairs
-module(permit_keyval).
-behaviour(pipe).

%% key-value api
-export([create/1, update/1, lookup/1, remove/1]).

%% 
-export([start_link/2, init/1, free/2, handle/3]).

%%-----------------------------------------------------------------------------
%%
%% key-value api
%%
%%-----------------------------------------------------------------------------

%%
%%
create(PubKey) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   pts:put(permit, Access, PubKey).

%%
%%
update(PubKey) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   pts:call(permit, Access, {update, Access, PubKey}).

%%
%%
lookup(Access) ->
   pts:get(permit, Access).

%%
%%
remove(PubKey) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   pts:remove(permit, Access).
   % pts:call(permit, Access, {remove, Access}).

%%-----------------------------------------------------------------------------
%%
%% default in-memory implementation
%%
%%-----------------------------------------------------------------------------

start_link(Ns, Access) ->
   pipe:start_link(?MODULE, [Ns, Access], []).

init([Ns, Access]) ->
   pns:register(Ns, Access, self()),
   {ok, handle, undefined}.

free(_, _PubKey) ->
   ok.

%%
handle({put, _Access, PubKey}, Pipe, undefined) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, handle, PubKey};

handle({put, _Access, _PubKey}, Pipe, PubKey) ->
   pipe:ack(Pipe, {error, conflict}),
   {next_state, handle, PubKey};

%%
handle({update, _Access, _PubKey}, Pipe, undefined) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, undefined};

handle({update, _Access, PubKey}, Pipe, _) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, handle, PubKey};

%%
handle({get, _Access}, Pipe, undefined) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, undefined};

handle({get, _Access}, Pipe, PubKey) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, handle, PubKey};

%%
handle({remove, _Access}, Pipe, undefined) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, undefined};

handle({remove, _Access}, Pipe, PubKey) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {stop, normal, PubKey}.
