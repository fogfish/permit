%% @doc
%%    public / private key management abstraction  
-module(permit_pubkey).
-include("permit.hrl").

-export([
   new/2
  ,auth/2
  ,create/2
  ,lookup/2
]).


%%
%% create new pubkey certificate 
new(Access, Secret) ->
   Salt = permit_hash:random(?CONFIG_SALT),
   Hash = permit_hash:sign(Secret, Salt),
   [
      {id,           Access}
     ,{<<"hash">>,   Hash}
     ,{<<"salt">>,   Salt}
      
      %% note: secret is not stored to persistent db
     ,{<<"secret">>, Secret}
   ].

%%
%% authenticate root account
%% entity might contain multiple instances of <<"hash">>, <<"salt">> due concurrency
%% use uid:g() as tx to filter most recent values
auth(Entity, Scope) ->
   [{id, Access}|_] = Ent = filter(Entity),
   auth(Access, Ent, Scope).

auth(Access, Entity, Scope) ->
   Pass = pair:x(<<"secret">>, Entity),
   Hash = pair:x(<<"hash">>,   Entity),
   Salt = pair:x(<<"salt">>,   Entity),
   Sign = permit_hash:sign(Pass, Salt),
   case permit_hash:eq(Sign, Hash) of
      true  ->
         {ok, token(pair:x(<<"account">>, Entity), Access, Scope)};
      false ->
         {error, unauthorized}
   end.

token(undefined, Account, Scope) ->
   permit_token:encode(
      permit_token:new(Scope, Account)
   );

token(Account, Access, Scope) ->
   permit_token:encode(
      permit_token:new(Scope, Account, Access)
   ).
   
%%
%% create pubkey entity to storage
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

