%% @doc
%%   public / private key pair i/o
-module(permit_pubkey_db).
-behaviour(pipe).

-compile({parse_transform, category}).
-include("permit.hrl").

%% key-value api
-export([create/1, update/1, lookup/1, remove/1, keys/1]).

%% 
-export([start_link/3, init/1, free/2, none/3, some/3]).

-record(state, {
   storage = undefined :: _
,  key     = undefined :: _
,  val     = undefined :: _
}).

%%-----------------------------------------------------------------------------
%%
%% key-value api
%%
%%-----------------------------------------------------------------------------

%%
%%
create(#pubkey{id = Key} = PubKey) ->
   pts:put(permit, Key, PubKey).

%%
%%
update(#pubkey{id = Key} = PubKey) ->
   pts:call(permit, Key, {update, PubKey}).

%%
%%
lookup({iri, _, _} = Key) ->
   pts:get(permit, Key);
lookup(#pubkey{id = Key}) ->
   pts:get(permit, Key).

%%
%%
remove(#pubkey{id = Key}) ->
   pts:remove(permit, Key).

%%
%%
keys({iri, _, _} = Key) ->
   pts:call(permit, Key, keys);
keys(#pubkey{id = Key}) ->
   pts:call(permit, Key, keys).

%%-----------------------------------------------------------------------------
%%
%% factory
%%
%%-----------------------------------------------------------------------------

start_link(Uri, Ns, Key) ->
   pipe:start_link(?MODULE, [Uri, Ns, Key], []).

init([{uri, _, _} = Uri, Ns, Key]) ->
   pns:register(Ns, Key, self()),
   case checkout(Uri, #state{key = Key}) of
      {ok, #state{val = undefined} = State} ->
         {ok, none, State};
      {ok, State} ->
         {ok, some, State}
   end.

free(_, _PubKey) ->
   ok.

%%-----------------------------------------------------------------------------
%%
%% state machine
%%
%%-----------------------------------------------------------------------------

%%
%%
none({put, _Key, PubKey}, Pipe, #state{} = State0) ->
   case commit(State0#state{val = PubKey}) of
      {ok, State1} ->
         pipe:ack(Pipe, {ok, PubKey}),
         {next_state, some, State1};
      {error,   _} = Error ->
         pipe:ack(Pipe, Error),
         {stop, normal, State0}
   end;

none({update, _PubKey}, Pipe, State) ->
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
%%
some({put, _Key, _PubKey}, Pipe, #state{} = State) ->
   %% Note: it is required to disable 'create' of existed key-pair
   %%       due to security concern. 
   pipe:ack(Pipe, {error, conflict}),
   {next_state, some, State};

some({update, PubKey}, Pipe, #state{} = State0) ->
   case commit(State0#state{val = PubKey}) of
      {ok, State1} ->
         pipe:ack(Pipe, {ok, PubKey}),
         {next_state, some, State1};
      {error,   _} = Error ->
         pipe:ack(Pipe, Error),
         {stop, normal, State0}
   end;

some({get, _Key}, Pipe, #state{val = PubKey} = State) ->
   pipe:ack(Pipe, {ok, PubKey}),
   {next_state, some, State};

some({remove, _Key}, Pipe, #state{val = PubKey} = State0) ->
   case revoke(State0) of
      {ok, State1} ->
         pipe:ack(Pipe, {ok, PubKey}),
         {stop, normal, State1};
      {error, _} = Error ->
         pipe:ack(Pipe, Error),
         {stop, normal, State0}
   end;

some(keys, Pipe, #state{} = State) ->
   pipe:ack(Pipe, pubkeys(State)),
   {next_state, some, State};

some(_, Pipe, State) ->
   pipe:ack(Pipe, {error, unsupported}),
   {next_state, some, State}.

%%-----------------------------------------------------------------------------
%%
%% state machine
%%
%%-----------------------------------------------------------------------------

%%
%%
checkout({uri, ephemeral, _}, #state{} = State) ->
   {ok, State#state{storage = ephemeral}};
checkout({uri, _, _} = Uri, #state{key = Key} = State) ->
   [Storage, _] = uri:schema(Uri),
   case Storage:get(#pubkey{id = Key}) of
      {ok, PubKey} ->
         {ok, State#state{storage = Storage, val = PubKey}};
      {error, _} ->
         {ok, State#state{storage = Storage}}
   end.

%%
%%
commit(#state{storage = ephemeral} = State) ->
   {ok, State};

commit(#state{storage = Storage, val = PubKey} = State) ->
   [either || Storage:put(PubKey), cats:unit(State)].

%%
%%
revoke(#state{storage = ephemeral} = State) ->
   {ok, State};

revoke(#state{storage = Storage, val = PubKey} = State) ->
   [either || Storage:remove(PubKey), cats:unit(State)].

%%
%%
pubkeys(#state{storage = ephemeral}) ->
   {ok, []};
pubkeys(#state{storage = Storage, key = {iri, Prefix, _}}) ->
   Storage:match(#pubkey{id = {iri, Prefix, undefined}}).
