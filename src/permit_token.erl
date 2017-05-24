%% @doc
%%   oauth token management
-module(permit_token).

-export([
   new/1,
   new/3,
   check/3,
   encode/1,
   decode/1
]).

-define(VSN,  1).
-define(PAD, 16).

%%
%%
new(Scope) ->
   #{version => ?VSN, t => os:timestamp(), scope => Scope}.

new(Master, Access, Scope) ->
   #{version => ?VSN, t => os:timestamp(), scope => Scope, master => Master, access => Access}.

%%
%%
check(TTL, Scope, Token)
 when is_binary(Token) ->
   check(TTL, Scope, decode(Token));
check(TTL, Scope, #{t := T, scope := List} = Token) ->
   case tempus:sub(os:timestamp(), TTL) of
      X when X < T ->
         case lists:member(Scope, List) of
            true  -> {ok, identity(Token)};
            false -> {error, unauthorized}
         end;
      _ ->
         {error, expired}
   end.

identity(#{master := undefined, access := Access}) ->
   Access;
identity(#{master := Master}) ->
   Master.

%%
%%
encode(Token) ->
   encode(aes, Token).

encode(aes, Token) ->
   SKey = base64:decode(opts:val(key, permit)),
   IVec = crypto:next_iv(aes_cbc, permit_hash:random(32)),
   Data = crypto:block_encrypt(aes_cbc, SKey, IVec, pad(erlang:term_to_binary(Token))),
   base64:encode(<<IVec:16/binary, Data/binary>>).

%%
%%
decode(Token) ->
   decode(aes, base64:decode(Token)).   

decode(aes, <<IVec:16/binary, Data/binary>>) ->
   SKey = base64:decode(opts:val(key, permit)),
   <<Len:16, Text:Len/binary, _/binary>> = crypto:block_decrypt(aes_cbc, SKey, IVec, Data),
   erlang:binary_to_term(Text).

%%-----------------------------------------------------------------------------
%%
%% private
%%
%%-----------------------------------------------------------------------------

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
