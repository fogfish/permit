
%%
%% access / secret key properties
-define(CONFIG_ACCESS, 15).
-define(CONFIG_SECRET, 30).

%%
%% access token
-define(CONFIG_TOKEN,  120).

%%
%%
-define(CONFIG_SALT,            32).
-define(CONFIG_PBKDF2_DK,      256).
-define(CONFIG_PBKDF2_HASH, sha256).
-define(CONFIG_PBKDF2_C,     65536). 

%%
%%
-define(CONFIG_SYS,          <<"sys">>).
-define(CONFIG_CACHE,      <<"token">>).
-define(CONFIG_CACHE_TTL,        43200).

-define(CONFIG_R,      2).  %% number of reader peers
-define(CONFIG_W,      2).  %% number of writer peers
