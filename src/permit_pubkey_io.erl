%% @doc
%%   public / private key pair i/o
-module(permit_pubkey_io).
-behaviour(pipe).

%% key-value api
-export([create/1, update/1, lookup/1, remove/1]).

%% 
-export([start_link/3, init/1, free/2, none/3, some/3]).

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

%%-----------------------------------------------------------------------------
%%
%% default in-memory implementation
%%
%%-----------------------------------------------------------------------------

start_link(_Uri, Ns, Access) ->
   pipe:start_link(?MODULE, [Ns, Access], []).

init([Ns, Access]) ->
   pns:register(Ns, Access, self()),
   {ok, none, undefined}.

free(_, _PubKey) ->
   ok.

%%
none({put, _Access, PubKey}, Pipe, _) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, some, PubKey};

none({update, _Access, _PubKey}, Pipe, State) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, State};

none({get, _Access}, Pipe, State) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, State};

none({remove, _Access}, Pipe, State) ->
   pipe:ack(Pipe, {error, not_found}),
   {stop, normal, State};

none(_, Pipe, State) ->
   pipe:ack(Pipe, {error, unsupported}),
   {stop, normal, State}.
   

%%
some({put, _Access, _PubKey}, Pipe, PubKey) ->
   pipe:ack(Pipe, {error, conflict}),
   {next_state, some, PubKey};

some({update, _Access, PubKey}, Pipe, _) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, some, PubKey};

some({get, _Access}, Pipe, PubKey) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, some, PubKey};

some({remove, _Access}, Pipe, PubKey) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {stop, normal, PubKey};

some(_, Pipe, State) ->
   pipe:ack(Pipe, {error, unsupported}),
   {next_state, some, State}.

