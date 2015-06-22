%% @doc
%%   account
-module(permit_pubkey).
-include("permit.hrl").

%% @todo: rename as account with multiple schema support (root, access, etc) + DAO ?

-export([
   new/3
  ,urn/2
  ,auth/2
  ,create/2
  ,lookup/2
]).


%%
%% new account object
new(Type, Access, Secret) ->
   Salt = permit_hash:random(?CONFIG_SALT),
   Hash = permit_hash:sign(Secret, Salt),
   [
      {id,           urn(Type, Access)}
     ,{<<"hash">>,   Hash}
     ,{<<"salt">>,   Salt}
      
      %% note: secret is not stored to persistent db
     ,{<<"secret">>, Secret}
   ].

%%
%%
urn(root,   Access) ->
   <<"urn:root:", Access/binary>>;
urn(pubkey, Access) ->
   <<"urn:pubkey:", Access/binary>>.


%%
%% authenticate root account
%% entity might contain multiple instances of <<"hash">>, <<"salt">> due concurrency
%% use uid:g() as tx to filter most recent values
auth(Cache, Entity) ->
   auth1(Cache, filter(Entity)).

auth1(Cache, Entity) ->
   Pass = pair:x(<<"secret">>, Entity),
   Hash = pair:x(<<"hash">>,   Entity),
   Salt = pair:x(<<"salt">>,   Entity),
   Sign = permit_hash:sign(Pass, Salt),
   case permit_hash:eq(Sign, Hash) of
      true  ->
         %% @todo: scope
         Token = permit_hash:key(?CONFIG_TOKEN),
         %% @todo: memcache:add + error handling
         memcache:put(Cache, Token, pair:x(id, Entity), [{w, ?CONFIG_W}]),
         {ok, Token};
      false ->
         {error, unauthorized}
   end.

%%
%% create entity to storage
create(Db, Entity) ->
   create_uid(Db, Entity).

create_uid(Db, Entity) ->
   case 
      thingz:uid(Db, pair:x(id, Entity), [{w, ?CONFIG_W}]) 
   of
      ok    -> 
         create_ent(Db, Entity);
      Error -> 
         Error
   end.   

create_ent(Db, Entity) ->
   case    
      thingz:entity(Db, pair:x(id, Entity), [k, {r, ?CONFIG_R}])
   of
      {ok,  []} -> 
         create_put(Db, Entity); 
      Result    ->
         Result       
   end.

create_put(Db, Entity) ->
   Ent = lists:keydelete(<<"secret">>, 1, Entity),
   case 
      thingz:put(Db, Ent, [{w, ?CONFIG_W}, {tx, uid:g()}])
   of
      ok    -> 
         {ok, Entity};
      Error -> 
         Error
   end.


lookup(Db, Entity) ->
   case
      thingz:entity(Db, pair:x(id, Entity), [k, {r, ?CONFIG_R}])
   of
      %% user do not exists      
      {error,[{badarg, _}]} ->
         {error, unauthorized};
      %% user do not exists
      {ok,    []} -> 
         {error, unauthorized};      
      %% system error
      {error, _} = Error -> 
         Error;
      %% user exists, authorize
      {ok, Value} ->
         {ok, Value ++ [{<<"secret">>, pair:x(<<"secret">>, Entity)}]} 
   end.   


%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
%% filter entity, return latest transaction
filter([{id, _} = Id  | Tail]) ->
   [Id | filter(Tail)];
filter([{_, _, _, Tx} | _]=Tail) ->
   filter(Tx, Tail);
filter(Tail) ->
   Tail.

filter(Tx, [{_, _} = H | T]) ->
   [H | filter(Tx, T)];
filter(Tx, [{P, O, _, Tx} | T]) ->
   [{P, O} | filter(Tx, T)];
filter(Tx, [_ | T]) ->
   filter(Tx, T);
filter(_, []) ->
   [].

