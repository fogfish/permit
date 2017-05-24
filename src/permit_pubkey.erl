%% @doc
%%    public / private key management abstraction  
-module(permit_pubkey).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/2
  ,access/0
  ,secret/0
  ,master/0
  ,nonsense/0
  ,authenticate/3

  % ,create/2
  % ,lookup/2
]).


%%
%% create new pubkey certificate 
new(Access, Secret) ->
   Nonsense = permit_hash:random(?CONFIG_SALT),
   {ok, [$.||
      lens:put(access(), Access, #{}),
      lens:put(secret(), permit_hash:sign(Secret, Nonsense), _),
      lens:put(nonsense(), Nonsense, _)
   ]}.

%%
%% 
access()   -> lens:map(<<"access">>,  undefined).
secret()   -> lens:map(<<"secret">>,  undefined).
master()   -> lens:map(<<"master">>,  undefined).
nonsense() -> lens:map(<<"nonsense">>, undefined).

%%
%% authenticate certificate, return a token with given scope
authenticate(Entity, Secret, Scope) ->
   Access   = lens:get(access(), Entity), 
   Master   = lens:get(master(), Entity), 
   Nonsense = lens:get(nonsense(), Entity),
   SignA    = lens:get(secret(), Entity),
   SignB    = permit_hash:sign(Secret, Nonsense),
   case permit_hash:eq(SignA, SignB) of
      true  ->
         {ok, token(Master, Access, Scope)};
      false ->
         {error, unauthorized}   
   end.


%% entity might contain multiple instances of <<"hash">>, <<"salt">> due concurrency
%% use uid:g() as tx to filter most recent values
% auth(Entity, Scope) ->
%    [{id, Access}|_] = Ent = filter(Entity),
%    auth(Access, Ent, Scope).

% auth(Access, Entity, Scope) ->
%    Pass = pair:x(<<"secret">>, Entity),
%    Hash = pair:x(<<"hash">>,   Entity),
%    Salt = pair:x(<<"salt">>,   Entity),
%    Sign = permit_hash:sign(Pass, Salt),
%    case permit_hash:eq(Sign, Hash) of
%       true  ->
%          {ok, token(pair:x(<<"account">>, Entity), Access, Scope)};
%       false ->
%          {error, unauthorized}
%    end.

token(Master, Access, Scope) ->
   permit_token:encode(
      permit_token:new(Master, Access, Scope)
   ).


% token(Account, Access, Scope) ->
%    permit_token:encode(
%       permit_token:new(Scope, Account, Access)
%    ).
   
%%
%% create pubkey entity to storage
% create(Db, Entity) ->
%    create_uid(Db, Entity).

% create_uid(Db, Entity) ->
%    {ok, Entity}.
   % case 
   %    thingz:uid(Db, pair:x(id, Entity), [{w, ?CONFIG_W}]) 
   % of
   %    ok    -> 
   %       create_ent(Db, Entity);
   %    Error -> 
   %       Error
   % end.   

% create_ent(Db, Entity) ->
%    case    
%       thingz:entity(Db, pair:x(id, Entity), [k, {r, ?CONFIG_R}])
%    of
%       {ok,  []} -> 
%          create_put(Db, Entity); 
%       Result    ->
%          Result       
%    end.

% create_put(Db, Entity) ->
%    Ent = lists:keydelete(<<"secret">>, 1, Entity),
%    case 
%       thingz:put(Db, Ent, [{w, ?CONFIG_W}, {tx, uid:g()}])
%    of
%       ok    -> 
%          {ok, Entity};
%       Error -> 
%          Error
%    end.


% lookup(Db, Entity) ->
%    case
%       thingz:entity(Db, pair:x(id, Entity), [k, {r, ?CONFIG_R}])
%    of
%       %% user do not exists      
%       {error,[{badarg, _}]} ->
%          {error, unauthorized};
%       %% user do not exists
%       {ok,    []} -> 
%          {error, unauthorized};      
%       %% system error
%       {error, _} = Error -> 
%          Error;
%       %% user exists, authorize
%       {ok, Value} ->
%          {ok, Value ++ [{<<"secret">>, pair:x(<<"secret">>, Entity)}]} 
%    end.   


%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
%% filter entity, return latest transaction
% filter([{id, _} = Id  | Tail]) ->
%    [Id | filter(Tail)];
% filter([{_, _, _, Tx} | _]=Tail) ->
%    filter(Tx, Tail);
% filter(Tail) ->
%    Tail.

% filter(Tx, [{_, _} = H | T]) ->
%    [H | filter(Tx, T)];
% filter(Tx, [{P, O, _, Tx} | T]) ->
%    [{P, O} | filter(Tx, T)];
% filter(Tx, [_ | T]) ->
%    filter(Tx, T);
% filter(_, []) ->
%    [].

