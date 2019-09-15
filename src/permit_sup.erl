-module(permit_sup).
-behaviour(supervisor).

-compile({parse_transform, generic}).
-compile({parse_transform, category}).
-include("permit.hrl").

-export([
   start_link/0
,  init/1
]).

%%
-define(CHILD(Type, I),            {I,  {I, start_link,   []}, permanent, 5000, Type, dynamic}).
-define(CHILD(Type, I, Args),      {I,  {I, start_link, Args}, permanent, 5000, Type, dynamic}).
-define(CHILD(Type, ID, I, Args),  {ID, {I, start_link, Args}, permanent, 5000, Type, dynamic}).

%%-----------------------------------------------------------------------------
%%
%% supervisor
%%
%%-----------------------------------------------------------------------------

start_link() ->
   supervisor:start_link({local, ?MODULE}, ?MODULE, []).
   
init([]) ->   
   {ok,
      {
         {one_for_one, 6, 900},
         cache_pubkey() ++ db_pubkey() ++ config()
      }
   }.

%%
%%
db_pubkey() ->
   db(#pubkey{}, labelled:encode(#pubkey{}), labelled:decode(#pubkey{})).

db(Type, Encode, Decode) ->
   db(storage(), Type, Encode, Decode).

db({uri, ephemeral, _}, _, _, _) ->
   [];
db(Uri, Type, Encode, Decode) ->
   [Backend, Schema] = uri:schema(Uri),
   [?CHILD(worker, erlang:element(1, Type), Backend, 
      [Type, uri:s(uri:schema(Schema, Uri)), Encode, Decode]
   )].

%%
%%
cache_pubkey() ->
   [?CHILD(supervisor, pts, [permit,
      [
         'read-through'
      ,  {factory, temporary}
      ,  {entity, {permit_pubkey_db, start_link, [storage()]}}
      ]
   ])].

storage() ->
   uri:new( opts:val(storage, "ephemeral://", permit) ).

%%
%%
config() ->
   [?CHILD(worker, permit_config)].
