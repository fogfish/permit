# permit

This library implements a high-level API for security tokens management. The library does not attempt to implement its own crypto. Instead, it heavily depends on external low-level crypto primitives, making them usable through simple use-case oriented API calls.

[![Build Status](https://secure.travis-ci.org/fogfish/permit.svg?branch=master)](http://travis-ci.org/fogfish/permit)
[![Coverage Status](https://coveralls.io/repos/github/fogfish/permit/badge.svg?branch=master)](https://coveralls.io/github/fogfish/permit?branch=master)


## Key features 

**Access/Secret** key pair represents the identity. The library applies a best practice of identity persistency. Systems should not store plain text, encrypted or hashed passwords. Instead, they should protect passwords with compute/memory intensive password derivation algorithms and salts. This library just defines a data model for an identity and abstract key-value I/O primitives to persist them on an external databases.

**Secret key** derivation is using a human-generated password and a salt to ensures that secret key used for signature of confidential data is chosen from large space, unlike human passwords. The library is configurable to use one of the password hashing algorithms: PBKDF2, scrypt, etc.
 
**Access token** is a string representing an authorization. The token denotes an identity of account, specific roles/actions/scopes and lifetime. The token is an abstraction of authorization constructs that replaces the usage of access/secret pairs with a single token understood by the system. This library uses JWT for this purpose.

**Roles** are permission policies in the system that determines what actions are available to the identity.

**Access identity** is an access/secret pair that is linked to master access/secret. The access identity allows to provision the access to the system without exposing the original keys to third-party services.  

**Only OTP/20.x** or later due to different behavior of `public_key:generate_key/1`

## Getting started

The latest version of the library is available at its `master` branch. All development, including new features and bug fixes, take place on the `master` branch using forking and pull requests as described in contribution guidelines.

```erlang
{deps, [
  {permit, ".*",
    {git, "https://github.com/fogfish/permit", {branch, master}}
  }
]}.
```

### Configuration

The library supports config either using [standard release config files](http://erlang.org/doc/man/config.html) or environment variables. Please see [example configuration](priv/app.config).

Please note that your application requires [AWS DynamoDB driver](https://github.com/fogfish/ddb) as dependency if you need to activate keys persistency feature. It is recommended to use following table schema

```yaml
MyTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub ${AWS::StackName}-pubkey
      AttributeDefinitions:
        - AttributeName: prefix
          AttributeType: S
        - AttributeName: suffix
          AttributeType: S

      KeySchema:
        - AttributeName: prefix
          KeyType: HASH
        - AttributeName: suffix
          KeyType: RANGE

      ProvisionedThroughput:
        ReadCapacityUnits: 1
        WriteCapacityUnits: 1
```

### Usage

```erlang
permit:start().

%%
%% create new identity
Access = {iri, <<"example.com">>, <<"joe">>}.
Secret = <<"secret">>.
Claims = #{<<"read">> => true, <<"write">> => true}.
permit:create(Access, Secret, Claims).

%%
%% allocate revocable token
{ok, Token} = permit:revocable(Access, Secret, 600, #{<<"read">> => true}).

%%
%% validate token and return claims associated with it
permit:validate(Token).
```

## JWT token structure

Please see a comprehensive specification of token attributes [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens). 

**`iss`** identifies the security token service (STS) that constructs and returns the token.

**`aud`** identifies intended recipient of the token. The application that receives the token must verify that the audience value is correct and reject any tokens intended for a different audience. 

**`sub`** identifies the principal about which the token asserts information, such as the user of an application.

**`idp`** records the identity provider that authenticated the subject of the token.

**`app`** identifies the application that is using the token to access a resource. 

**`rev`**  identifies the revocable token 


## How To Contribute

The library is [Apache 2.0](LICENSE) licensed and accepts contributions via GitHub pull requests:

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

The development requires [Erlang/OTP](http://www.erlang.org/downloads) version 19.0 or later and essential build tools.

**Build** and **run** service in your development console. The following command boots Erlang virtual machine and opens Erlang shell.

```bash
git clone https://github.com/fogfish/permit
cd permit
make
make run
```

### commit message

The commit message helps us to write a good release note, speed-up review process. The message should address two question what changed and why. The project follows the template defined by chapter [Contributing to a Project](http://git-scm.com/book/ch5-2.html) of Git book.

>
> Short (50 chars or less) summary of changes
>
> More detailed explanatory text, if necessary. Wrap it to about 72 characters or so. In some contexts, the first line is treated as the subject of an email and the rest of the text as the body. The blank line separating the summary from the body is critical (unless you omit the body entirely); tools like rebase can get confused if you run the two together.
> 
> Further paragraphs come after blank lines.
> 
> Bullet points are okay, too
> 
> Typically a hyphen or asterisk is used for the bullet, preceded by a single space, with blank lines in between, but conventions vary here
>
>

### bugs

If you experience any issues with the library, please let us know via [GitHub issues](https://github.com/fogfish/permit/issue). We appreciate detailed and accurate reports that help us to identity and replicate the issue. 

* **Specify** the configuration of your environment. Include which operating system you use and the versions of runtime environments. 

* **Attach** logs, screenshots and exceptions, in possible.

* **Reveal** the steps you took to reproduce the problem, include code snippet or links to your project.


## Licensee

[![See LICENSE](https://img.shields.io/github/license/fogfish/permit.svg?style=for-the-badge)](LICENSE)
