# permit

The library implements a high-level api for security tokens management. The library do not attempt to implement own crypto, instead it is heavily depends on external low-level crypto primitives, making them usable through simple use-case oriented api calls.

[![Build Status](https://secure.travis-ci.org/fogfish/permit.svg?branch=master)](http://travis-ci.org/fogfish/permit) [![Coverage Status](https://coveralls.io/repos/github/fogfish/permit/badge.svg?branch=master)](https://coveralls.io/github/fogfish/permit?branch=master)


## Key features 

**Access/Secret** key pair represents the account/identity. The library applies a best practice of account storage. Systems should not store plain text, encrypted or hashed passwords. Instead, compute/memory intensive password derivation algorithms and salt shall be used to protect passwords. The library defines a data model for an account and abstract key-value storage I/O primitives to persist them on external database.  

**Secret key** derivation is using human-generated password and a salt to ensures that secret key used for signature of confidential data is chosen from large space, unlike human passwords. The library is configurable to use one of the password hashing algorithms: PBKDF2, scrypt, etc.
 
**Access token** is a string representing an authorization. The token denotes an identity of account, specific roles/actions/scopes and lifetime. The token is an abstraction of authorization constructs that replaces the usage of access/secret pairs with a single token understood by the system.

**Roles** are permission policies in the system that determines what actions are available to the identity.

**Access identity** is an access/secret pair that is linked to master access/secret. The access identity allows to provision the access to system without exposing the original keys to third-party services.  


## Token structure

**`iss`** identifies the security token service (STS) that constructs and returns the token.

**`aud`** identifies intended recipient of the token. The application that receives the token must verify that the audience value is correct and reject any tokens intended for a different audience. 

**`sub`** identifies the principal about which the token asserts information, such as the user of an application.

**`idp`** records the identity provider that authenticated the subject of the token.

**`app`** identifies the application that is using the token to access a resource. 

**`rev`**  identifies the revocable token 
