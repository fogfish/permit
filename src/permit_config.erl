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
   provider = undefined :: binary(),
   public   = undefined :: binary(),
   secret   = undefined :: binary()
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
   {ok, handle, 
      seed(#state{provider = opts:val(keypair, permit_config_rsa, permit)})
   }.


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
seed(#state{provider = Provider} = State) ->
   case Provider:keypair() of
      {ok, Public, Secret} ->
         State#state{public = Public, secret = Secret};
      {ok, Public} ->
         State#state{public = Public}
   end.
