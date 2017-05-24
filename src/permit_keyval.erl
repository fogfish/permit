%% @doc
%%   key / value interface to manage access credentials
-module(permit_keyval).

-export([
   create/1,
   lookup/1,
   remove/1
]).


%%
%%
create(Entity) ->
   Access = lens:get(permit_pubkey:access(), Entity),
   eitherT(pts:put(permit, Access, Entity), Entity).

%%
%%
lookup(Access) ->
   eitherT(pts:get(permit, Access), undefined).

%%
%%
remove(Entity) ->
   Access = lens:get(permit_pubkey:access(), Entity),
   pts:remove(permit, Access).


eitherT(ok, Entity) ->
   {ok, Entity};

eitherT({error, _} = Error, _) ->
   Error;

eitherT(Entity, _) ->
   {ok, Entity}.


