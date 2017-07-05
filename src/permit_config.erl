%% @doc
%%    
-module(permit_config).

-export([public/0, secret/0]).
-export([
   start_link/0,
   init/1,
   free/2,
   handle/3
]).

%%
-record(state, {
   public = undefined :: binary(),
   secret = undefined :: binary()
}).

%%
%% API
public() ->
   pipe:call(?MODULE, public).

secret() ->
   pipe:call(?MODULE, secret).

%%
%%
start_link() ->
   pipe:start_link({local, ?MODULE}, ?MODULE, [], []).   

init(_) ->
   {ok, handle, seed(#state{})}.

free(_, _) ->
   ok.

handle(public, Pipe, #state{public = Public} = State) ->
   pipe:ack(Pipe, {ok, Public}),
   {next_state, handle, State};

handle(secret, Pipe, #state{secret = Secret} = State) ->
   pipe:ack(Pipe, {ok, Secret}),
   {next_state, handle, State}.

%%
%%
seed(State) ->
   seed_public( seed_secret(State) ).

seed_secret(State) ->
   Uri = uri:new(opts:val(secret, permit)),
   State#state{secret = seed_key(Uri)}.

seed_public(State) ->
   Uri = uri:new(opts:val(public, permit)),
   State#state{public = seed_key(Uri)}.

seed_key({uri, data, _} = Uri) ->
   Key  = uri:path(Uri),
   [ RSAEntry ] = public_key:pem_decode(base64:decode(Key)),
   public_key:pem_entry_decode(RSAEntry);
   
seed_key({uri, file, _} = Uri) ->
   Path = uri:path(Uri),
   {ok, Key} = file:read_file(Path),
   [ RSAEntry ] = public_key:pem_decode(base64:decode(Key)),
   public_key:pem_entry_decode(RSAEntry).

