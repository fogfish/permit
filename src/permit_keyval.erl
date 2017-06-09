%% @doc
%%   key / value interface to manage pubkey pairs
-module(permit_keyval).

-export([
   create/1,
   lookup/1,
   remove/1
]).


%%
%%
create(PubKey) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   eitherT(pts:put(permit, Access, PubKey), PubKey).

%%
%%
lookup(Access) ->
   eitherT(pts:get(permit, Access), undefined).

%%
%%
remove(PubKey) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   pts:call(permit, Access, {ttl, 0}).


eitherT(ok, PubKey) ->
   {ok, PubKey};

eitherT({error, _} = Error, _) ->
   Error;

eitherT(PubKey, _) ->
   {ok, PubKey}.


