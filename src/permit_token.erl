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

% -define(VSN,  1).
% -define(PAD, 16).
-define(NONE,  <<"undefined">>).

%%
%%
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
%%
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
      identity(_)
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
   A = lens:get(ttl(), Token),
   case tempus:s(os:timestamp()) of 
      B when B < A ->
         {ok, Token};
      _ ->
         {error, expired}
   end.

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







% %%
% %%
% check(TTL, Scope, Token)
%  when is_binary(Token) ->
%    check(TTL, Scope, decode(Token));
% check(TTL, Scope, #{t := T, scope := List} = Token) ->
%    case tempus:sub(os:timestamp(), TTL) of
%       X when X < T ->
%          case lists:member(Scope, List) of
%             true  -> {ok, identity(Token)};
%             false -> {error, unauthorized}
%          end;
%       _ ->
%          {error, expired}
%    end.

identity(Token) ->
   Access = lens:get(access(), Token),
   Master = lens:get(master(), Token),
   {ok, [$. ||
      lens:put(master(), Master, #{}),
      lens:put(access(), Access, _)
   ]}.

%    case lens:get(master(), Token) of
%       <<"undefined">> ->
      
%    end.

% identity(#{master := undefined, access := Access}) ->
%    Access;
% identity(#{master := Master}) ->
%    Master.

%%
%%
encode(Token) ->
   base64:encode(erlang:term_to_binary(Token)).
%    % encode(aes, Token).

% encode(aes, Token) ->
%    SKey = base64:decode(opts:val(key, permit)),
%    IVec = crypto:next_iv(aes_cbc, permit_hash:random(32)),
%    Data = crypto:block_encrypt(aes_cbc, SKey, IVec, pad(erlang:term_to_binary(Token))),
%    base64:encode(<<IVec:16/binary, Data/binary>>).

%%
%%
decode(Token) ->
   erlang:binary_to_term(base64:decode(Token)).

%    decode(aes, base64:decode(Token)).   

% decode(aes, <<IVec:16/binary, Data/binary>>) ->
%    SKey = base64:decode(opts:val(key, permit)),
%    <<Len:16, Text:Len/binary, _/binary>> = crypto:block_decrypt(aes_cbc, SKey, IVec, Data),
%    erlang:binary_to_term(Text).

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

%%
%% pad message to 16-byte blocks
% pad(Msg) ->
%    Len = byte_size(Msg),
%    case (Len + 2) rem ?PAD of
%       0 ->
%          <<Len:16, Msg/binary>>;
%       N ->
%          Pad = permit_hash:random(?PAD - N),  
%          <<Len:16, Msg/binary, Pad/binary>>
%    end.
