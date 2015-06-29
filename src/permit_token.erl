%% @doc
%%   oauth token management
-module(permit_token).

-export([
   new/2,
   new/3,
   new/4,
   check/2,
   encode/1,
   decode/1
]).

-define(VSN,  1).
-define(PAD, 16).

%%
%%
new(TTL, Scope) ->
   #{version => ?VSN, t => tempus:add(os:timestamp(), TTL), scope => Scope}.

new(TTL, Scope, Account) ->
   #{version => ?VSN, t => tempus:add(os:timestamp(), TTL), scope => Scope, account => Account}.

new(TTL, Scope, Account, Access) ->
   #{version => ?VSN, t => tempus:add(os:timestamp(), TTL), scope => Scope, account => Account, access => Access}.

%%
%%
check(Scope, Token)
 when is_binary(Token) ->
   check(Scope, decode(Token));
check(Scope, #{t := T, scope := List}) ->
   case os:timestamp() of
      X when X < T ->
         lists:member(Scope, List);
      _ ->
         false
   end.

%%
%%
encode(Token) ->
   encode(aes, Token).

encode(aes, Token) ->
   SKey = base64:decode(opts:val(key, permit)),
   IVec = crypto:next_iv(aes_cbc, permit_hash:random(32)),
   Data = crypto:block_encrypt(aes_cbc128, SKey, IVec, pad(erlang:term_to_binary(Token))),
   base64:encode(<<IVec:16/binary, Data/binary>>).

%%
%%
decode(Token) ->
   decode(aes, base64:decode(Token)).   

decode(aes, <<IVec:16/binary, Data/binary>>) ->
   SKey = base64:decode(opts:val(key, permit)),
   <<Len:16, Text:Len/binary, _/binary>> = crypto:block_decrypt(aes_cbc128, SKey, IVec, Data),
   erlang:binary_to_term(Text).

%%
%% pad message to 16-byte blocks
pad(Msg) ->
   Len = byte_size(Msg),
   case (Len + 2) rem ?PAD of
      0 ->
         <<Len:16, Msg/binary>>;
      N ->
         Pad = permit_hash:random(?PAD - N),  
         <<Len:16, Msg/binary, Pad/binary>>
   end.

