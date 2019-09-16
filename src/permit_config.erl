%% @doc
%%    
-module(permit_config).

-export([
   public/0
,  secret/0
,  iss/0
,  aud/0
,  claims/0
,  keypair/0
,  keypair_ttl/0
,  storage/0
,  jwks/0
]).
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

%%-----------------------------------------------------------------------------
%%
%% config api
%%
%%-----------------------------------------------------------------------------

public() ->
   pipe:call(?MODULE, public).

secret() ->
   pipe:call(?MODULE, secret).

iss() ->
   typecast:s(value("PERMIT_ISSUER", issuer)).

aud() ->
   typecast:s(value("PERMIT_AUDIENCE", audience)).

claims() ->
   typecast:s(value("PERMIT_CLAIMS", claims)).

keypair() ->
   typecast:a(value("PERMIT_KEYPAIR", keypair, permit_config_rsa)).

keypair_ttl() ->
   value("PERMIT_KEYPAIR_TTL", keypair_ttl, undefined).

storage() ->
   uri:new(value("PERMIT_STORAGE", storage, "ephemeral://")).

jwks() ->
   scalar:c(value("PERMIT_JWKS", jwks)).

%%-----------------------------------------------------------------------------
%%
%% config server
%%
%%-----------------------------------------------------------------------------

start_link() ->
   pipe:start_link({local, ?MODULE}, ?MODULE, [], []).   

init(_) ->
   refresh(),
   {ok, handle, 
      seed(#state{provider = keypair()})
   }.


free(_, _) ->
   ok.

handle(public, Pipe, #state{public = Public} = State) ->
   pipe:ack(Pipe, {ok, Public}),
   {next_state, handle, State};

handle(secret, Pipe, #state{secret = Secret} = State) ->
   pipe:ack(Pipe, {ok, Secret}),
   {next_state, handle, State};

handle(seed, _, State) ->
   refresh(),
   {next_state, handle, seed(State)}.

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
%%
seed(#state{provider = Provider} = State) ->
   case Provider:keypair() of
      {ok, Public, Secret} ->
         State#state{public = Public, secret = Secret};
      {ok, Public} ->
         State#state{public = Public}
   end.

%%
%%
refresh() ->
   case keypair_ttl() of
      undefined ->
         ok;
      T ->
         erlang:send_after(typecast:i(T), self(), seed)
   end.

%%
%%
value(Env, Key) ->
   case os:getenv(Env) of
      false ->
         opts:val(Key, permit);
      Value ->
         Value
   end.

value(Env, Key, Default) ->
   case os:getenv(Env) of
      false ->
         opts:val(Key, Default, permit);
      Value ->
         Value
   end.