%% @doc
%%    
-module(permit_config).

-export([public/0, secret/0, config/0]).
-export([
   start_link/0,
   init/1,
   free/2,
   handle/3
]).

%%
-record(state, {
   public = undefined :: binary(),
   secret = undefined :: binary(),
   reload = undefined :: tempus:timer()
}).

%%
%% API
public() ->
   pipe:call(?MODULE, public).

secret() ->
   pipe:call(?MODULE, secret).

config() ->
   pipe:call(?MODULE, config).

%%
%%
start_link() ->
   pipe:start_link({local, ?MODULE}, ?MODULE, [], []).   

init(_) ->
   {ok, handle, 
      seed(
         #state{
            reload = tempus:timer(opts:val(reload, permit), config)
         }
      )
   }.

free(_, _) ->
   ok.

handle(public, Pipe, #state{public = Public} = State) ->
   pipe:ack(Pipe, {ok, Public}),
   {next_state, handle, State};

handle(secret, Pipe, #state{secret = Secret} = State) ->
   pipe:ack(Pipe, {ok, Secret}),
   {next_state, handle, State};

handle(config, _, #state{reload = T} = State) ->
   {next_state, handle, seed(State#state{reload = tempus:reset(T, config)})}.

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
   public_key:pem_entry_decode(RSAEntry);

seed_key({uri, https, _} = Uri) ->
   {ok, Json} = esh:run([sh, which(http), uri:s(Uri), "2> /dev/null"]),
   {ok, Key}  = jwk:decode(<<"jwt">>, scalar:s(Json)),
   Key;

seed_key({uri, [openssl, secret], _} = Uri) ->
   {ok, PEM} = esh:run([sh, which(openssl), secret, uri:path(Uri), "2> /dev/null"]),
   [ RSAEntry ] = public_key:pem_decode(scalar:s(PEM)),
   public_key:pem_entry_decode(RSAEntry);

seed_key({uri, [openssl, public], _} = Uri) ->
   {ok, PEM} = esh:run([sh, which(openssl), public, uri:path(Uri), "2> /dev/null"]),
   [ RSAEntry ] = public_key:pem_decode(scalar:s(PEM)),
   public_key:pem_entry_decode(RSAEntry);

seed_key({uri, Schema, _} = Uri) ->
   {ok, Json} = esh:run([sh, which(Schema), uri:s(Uri), "2> /dev/null"]),
   {ok, Key}  = jwk:decode(<<"jwt">>, scalar:s(Json)),
   Key.

%%
%%
which(Script) ->
   filename:join([
      code:priv_dir(permit),
      "scripts",
      scalar:c(Script) ++ ".sh"
   ]).

