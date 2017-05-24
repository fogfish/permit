%% @doc
%%   key / value interface to manage access credentials
-module(permit_keyval).

-export([
   create/1,
   lookup/1
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



eitherT(ok, Entity) ->
   {ok, Entity};

eitherT({error, _} = Error, _) ->
   Error;

eitherT(Entity, _) ->
   {ok, Entity}.


