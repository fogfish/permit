%% @doc
%%   security token
-module(permit_token).
-include("permit.hrl").
-compile({parse_transform, category}).

-export([
   new/3,

   ttl/0,
   roles/0,
   master/0,
   access/0,
   version/0,
   signature/0,

   check/3,
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
   {ok, [$. ||
      lens:put(version(), ?VSN, #{}),
      lens:put(ttl(), expired(TTL),  _),
      lens:put(access(), Access,  _),
      lens:put(master(), Master, _),
      lens:put(roles(), roles(Roles), _),
      signature(Secret, _)
   ]}.

%%
%% token attributes
ttl()     -> lens:map(<<"ttl">>, ?NONE).
roles()   -> lens:map(<<"roles">>, []).
master()  -> lens:map(<<"master">>, ?NONE).
access()  -> lens:map(<<"access">>, ?NONE).
version() -> lens:map(<<"version">>, ?NONE).
signature() -> lens:map(<<"signature">>, ?NONE).


%%
%% check validity of token
check(Token, Secret, Roles)
 when is_binary(Token) ->
   [either ||
      decode(Token),
      check(_, Secret, Roles)
   ];

check(Token, Secret, Roles)
 when is_map(Token) ->
   [either ||
      check_signature(Secret, Token),
      check_roles(Roles, _),
      check_ttl(_),
      check_return_identity(_)
   ].

check_signature(Secret, Token) ->
   SignTa = lens:get(signature(), Token),
   SignTb = lens:get(signature(), signature(Secret, Token)),
   case permit_hash:eq(SignTa, SignTb) of
      true  ->
         {ok, Token};
      false ->
         {error, unauthorized}
   end. 

check_roles_scope(Ra, Rb) ->
   A = gb_sets:from_list(roles(Ra)),
   B = gb_sets:from_list(roles(Rb)),
   gb_sets:to_list(gb_sets:intersection(A, B)).

check_roles([], Token) ->
   {ok, Token};

check_roles(Roles, Token) ->
   case check_roles_scope(lens:get(roles(), Token), Roles) of
      [] ->
         {error, scopes};
      Rx ->
         {ok, lens:put(roles(), Rx, Token)}
   end.

check_ttl(Token) ->
   case 
      lens:get(ttl(), Token) - tempus:s()
   of
      X when X > 0 ->
         {ok, Token};
      _ ->
         {error, expired}
   end.

check_return_identity(Token) ->
   Seed = case lens:get(master(), Token) of
      undefined -> #{};
      Master    -> lens:put(master(), Master, #{})
   end,
   {ok, [$. ||
      fmap(Seed),
      lens:put(access(), lens:get(access(), Token), _),
      lens:put(roles(),  lens:get(roles(), Token), _)
   ]}.

%%
%%
encode(Token) ->
   {ok, base64:encode(erlang:term_to_binary(Token))}.

%%
%%
decode(Token) ->
   {ok, erlang:binary_to_term(base64:decode(Token))}.

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------


%%
expired(TTL) ->
   tempus:s() + TTL.

%%
roles(Roles) ->
   lists:usort([scalar:s(X) || X <- Roles]).

%%
signature(Secret, Token) ->
   ToSign = lists:join(<<$\n>>, [
      scalar:s(lens:get(version(), Token)),
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
      sign(_,     <<"permit_token">>)
   ].

%%
%%
sign(Key, Data) ->
   crypto:hmac(sha256, Key, Data).


