%% @doc
%%    
-module(permit_config).
-include_lib("public_key/include/OTP-PUB-KEY.hrl").

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
   {ok, handle, 
      seed(#state{})
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
seed(State) ->
   #'RSAPrivateKey'{
      modulus = N, 
      publicExponent = E} = Secret = public_key:generate_key({rsa, 2048, 65537}),
   Public = #'RSAPublicKey'{modulus = N, publicExponent = E},
   State#state{public = Public, secret = Secret}.
