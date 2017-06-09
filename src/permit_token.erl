%% @doc
%%   security token
-module(permit_token).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/3,
   check/2,
   encode/1,
   decode/1
]).

-define(NONE,  <<"undefined">>).

%%
%% create new token with given ttl and roles
new(PubKey, TTL, Roles) ->
   Access = lens:get(permit_pubkey:access(), PubKey),
   Master = lens:get(permit_pubkey:master(), PubKey),
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   [$. ||
      lens:put(version(), ?VSN, #{}),
      lens:put(uid(), identity(), _),
      lens:put(ttl(), expired(TTL),  _),
      lens:put(access(), Access,  _),
      lens:put(master(), Master, _),
      lens:put(roles(), roles(Roles), _),
      signature(Secret, _)
   ].

%%
%% token attributes
uid()     -> lens:map(<<"uid">>, ?NONE).
ttl()     -> lens:map(<<"ttl">>, ?NONE).
roles()   -> lens:map(<<"roles">>, []).
master()  -> lens:map(<<"master">>, ?NONE).
access()  -> lens:map(<<"access">>, ?NONE).
version() -> lens:map(<<"version">>, ?NONE).
signature() -> lens:map(<<"signature">>, ?NONE).


%%
%% check validity of token
check(Token, Roles)
 when is_binary(Token) ->
   check(decode(Token), Roles);

check(Token, Roles)
 when is_map(Token) ->
   [either ||
      permit_keyval:lookup(lens:get(access(), Token)),
      check(_, Token, Roles)
   ].

check(PubKey, Token, Roles) ->
   [either ||
      check_signature(PubKey, Token),
      check_roles(PubKey, _, Roles),
      check_ttl(_),
      check_pair(_)
   ].

check_signature(PubKey, Token) ->
   Secret = lens:get(permit_pubkey:secret(), PubKey),
   SignTa = lens:get(signature(), Token),
   SignTb = lens:get(signature(), signature(Secret, Token)),
   case permit_hash:eq(SignTa, SignTb) of
      true  ->
         {ok, Token};
      false ->
         {error, unauthorized}
   end. 

check_roles(PubKey, Token, []) ->
   A = gb_sets:from_list( lens:get(roles(), Token) ), 
   B = gb_sets:from_list( lens:get(permit_pubkey:roles(), PubKey) ),
   case gb_sets:to_list(gb_sets:intersection(A, B)) of
      [] ->
         {error, unauthorized};
      _  ->
         {ok, Token}
   end;

check_roles(PubKey, Token, Roles) ->
   A = gb_sets:from_list( lens:get(roles(), Token) ), 
   B = gb_sets:from_list( lens:get(permit_pubkey:roles(), PubKey) ),
   C = gb_sets:from_list( [scalar:s(X) || X <- Roles] ),
   case gb_sets:to_list(gb_sets:intersection(C, gb_sets:intersection(A, B))) of
      [] ->
         {error, unauthorized};
      _  ->
         {ok, Token}
   end.

check_ttl(Token) ->
   case 
      lens:get(ttl(), Token) - tempus:s(os:timestamp())
   of
      X when X > 0 ->
         {ok, Token};
      _ ->
         {error, expired}
   end.

check_pair(Token) ->
   {ok, [$. ||
      fmap(#{}),
      lens:put(master(), lens:get(master(), Token), _),
      lens:put(access(), lens:get(access(), Token), _)
   ]}.

%%
%%
encode(Token) ->
   base64:encode(erlang:term_to_binary(Token)).

%%
%%
decode(Token) ->
   erlang:binary_to_term(base64:decode(Token)).


%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
identity() ->
   << <<X:8>> || <<X:8>> <= base64:encode(uid:encode(uid:g())), X =/= $= >>.

%%
expired(TTL) ->
   tempus:s(os:timestamp()) + TTL.

%%
roles(Roles) ->
   [scalar:s(X) || X <- Roles].

%%
signature(Secret, Token) ->
   ToSign = lists:join(<<$\n>>, [
      scalar:s(lens:get(version(), Token)),
      scalar:s(lens:get(uid(), Token)),
      scalar:s(lens:get(ttl(), Token)),
      scalar:s(lens:get(access(), Token)),
      scalar:s(lens:get(master(), Token)),
      scalar:s(lists:join(<<$ >>, lens:get(roles(), Token)))
   ]),
   Signature = bits:btoh(sign(signing_key(Secret, Token), ToSign)),
   lens:put(signature(), Signature, Token).

signing_key(Secret, Token) ->
   [$. ||
      sign(Secret, scalar:s(lens:get(ttl(), Token))),
      sign(_,      scalar:s(lens:get(uid(), Token))),
      sign(_,      scalar:s(lens:get(master(), Token))),
      sign(_,     <<"permit_token">>)
   ].

%%
%%
sign(Key, Data) ->
   crypto:hmac(sha256, Key, Data).
