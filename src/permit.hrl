
%%
%% length of access / secret keys
-define(CONFIG_ACCESS, 15).
-define(CONFIG_SECRET, 30).

%%
%% version of token
-define(VSN,  1).

%%
%% token time to live properties
-define(CONFIG_TTL_MASTER,   3600). %%  1h
-define(CONFIG_TTL_ACCESS,  43200). %% 12h

%%
%% password derive function attributes
-define(CONFIG_SALT,            32).
-define(CONFIG_PBKDF2_DK,      256).
-define(CONFIG_PBKDF2_HASH, sha256).
-define(CONFIG_PBKDF2_C,     65536). 

