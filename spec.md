%%%
title = "OpenID Connect Credential Provider"
abbrev = "OpenID Connect Credential Provider"
ipr = "none"
workgroup = "none"
keyword = [""]
#date = 2020-04-028T00:00:00Z

[seriesInfo]
name = "Individual-Draft"
value = "openid-credential-provider-01"
status = "informational"

[[author]]
initials = "T."
surname = "Looker"
fullname = "Tobias Looker"
#role = "reviewer"
organization = "MATTR Ltd"
[author.address]
email = "tobias.looker@mattr.global"

[[author]]
initials = "J."
surname = "Thompson"
fullname = "John Thompson"
#role = "editor"
organization = "MATTR Ltd"
[author.address]
email = "john.thompson@mattr.global"
%%%

.# Abstract

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables relying parties to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User.

In typical deployments of OpenID Connect today to be able to exercise the identity an End-User has with an OpenID Provider with a relying party, the relying party must be in direct contact with the provider. This constraint causes issues such as  [relying party tracking](https://github.com/WICG/WebID#the-rp-tracking-problem).

This specification defines how an OpenID provider can be extended beyond being the provider of simple identity assertions into being the provider of credentials.

{mainmatter}

# Introduction {#Introduction}

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables relying parties to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User.

In typical deployments of OpenID Connect today to be able to exercise the identity an End-User has with an OpenID Provider with a relying party, the relying party must be in direct contact with the provider. This constraint causes issues such as  [relying party tracking](https://github.com/WICG/WebID#the-rp-tracking-problem).

This specification defines how the OpenID Connect protocol can be extended so that a supporting Client can obtain a credential on-behalf of an End-User. Where a credential is defined as an assertion about the End-User which is bound to the Client in an authenticatable manner based on public/private key cryptography. This feature then enables the Client to onward present the credential to other relying parties whilst authenticating the established binding to the assertion.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 `@!RFC2119`.

In the .txt version of this document, values are quoted to indicate that they are to be taken literally. When using these values in protocol messages, the quotes MUST NOT be used as part of the value. In the HTML version of this document, values to be taken literally are indicated by the use of this fixed-width font.

All uses of JSON Web Signature (JWS) [JWS](https://tools.ietf.org/html/rfc7515) and JSON Web Encryption (JWE) [JWE](https://tools.ietf.org/html/rfc7516) data structures in this specification utilize the JWS Compact Serialization or the JWE Compact Serialization; the JWS JSON Serialization and the JWE JSON Serialization are not used.

## Terminology {#Terminology}

This specification uses the terms defined in OpenID Connect Core 1.0; in addition, the following terms are also defined:

Credential
: An assertion containing claims made about an End-User that has been bound in an authenticatable manner through the use of public/private key pairs to the requesting Client.

Credential Request
: An OpenID Connect Authentication Request that results in the End-User being authenticated by the Authorization Server and the Client receiving a credential about the authenticated End-User.

Holder
: An entity that is tasked with holding credential(s) and presenting them to relying parties and the consent of and on behalf of the End-User (subject of the credential(s)). 

## Overview

This specification extends the OpenID Connect protocol for the purposes of credential issuance.

1. The Holder acting as an OpenID Client sends a Credential Request to the Credential Provider that is acting as an OpenID Provider (OP).
2. The Credential Provider authenticates the End-User and obtains authorization.
3. The Credential Provider responds with a Credential.

These steps are illustrated in the following diagram:

```
+--------+                                   +----------+
|        |                                   |          |
|        |---(1)OpenID Credential Request--->|          |
|        |                                   |          |
|        |  +--------+                       |          |
|        |  |        |                       |          |
| Holder |  |  End-  |<--(2) AuthN & AuthZ-->|Credential|
|(Client)|  |  User  |                       | Provider |
|        |  |        |                       |   (OP)   |
|        |  +--------+                       |          |
|        |                                   |          |
|        |<--(3)OpenID Credential Response---|          |
|        |                                   |          |
+--------+                                   +----------+
```

**Note** - Outside of the scope for this specification is how the Holder then exercises presentation of this credential with a relying party, however the diagram looks like the following.

1. The Relying Party acting as an OpenID Client sends an OpenID Request to the Holder that is acting an OpenID Provider (OP).
2. The Holder authenticates the End-User and obtains authorization.
3. The Holder responds with a Credential Presentation.

```
+----------+                                                           +----------+
|          |                                                           |          |
|          |---(1)OpenID Connect Credential Presentation Request------>|          |
|          |                                                           |          |
|          |                          +--------+                       |          |
|          |                          |        |                       |          |
| Relying  |                          |  End-  |<--(2) AuthN & AuthZ-->|  Holder  |
|  Party   |                          |  User  |                       |   (OP)   |
| (Client) |                          |        |                       |          |
|          |                          +--------+                       |          |
|          |                                                           |          |
|          |<--(3)OpenID Connect Credential Presentation Response------|          |
|          |                                                           |          |
+----------+                                                           +----------+
```

# Credential Request

A Credential Request is an OpenID Connect authentication request made by a Holder that requests the End-User to be authenticated by the Credential Provider and consent be granted for a credential containing the requested claims about the End-User be issued to it.

The following section outlines how an [OpenID Connect Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) is extended in order to become a valid Credential Request.

## Credential Request

The simplest OpenID Connect Credential Request is an ordinary OpenID Connect request that makes use of one additional scope, `openid_credential`.

A non-normative example of the Credential Request.

```
HTTP/1.1 302 Found
Location: https://server.example.com/authorize?
  response_type=code
  &scope=openid%20openid_credential
  &client_id=s6BhdRkqt3
  &state=af0ifjsldkj
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
  &credential_format=w3cvc-jsonld
```

When a request of this nature is made, the `access_token` issued to the Client authorizes it to access the credential endpoint to obtain a credential.

## Signed Credential Request

When making a credential request, the Client can elect to sign the request, making use of the [signed request object](https://openid.net/specs/openid-connect-core-1_0.html#SignedRequestObject) defined in OpenID Connect Core.

The following example documents this variation.

A non-normative example of a Signed Credential request.

```
https://issuer.example.com/authorize
?scope=openid%20openid_credential
&request=<signed-jwt-request-obj>
```

Where the decoded payload of the request parameter is as follows

```
{
  "response_type": "code",
  "client_id": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "sub_jwk" : {
    "crv":"secp256k1",
    "kid":"YkDpvGNsch2lFBf6p8u3",
    "kty":"EC",
    "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
  },
  "redirect_uri": "https://client.example.com/callback",
  "credential_format": "w3cvc-jsonld"
}
```

Where the jwt was signed by the key referenced in the `sub_jwk` section of the request.

When a request of this nature is made, the resulting credential will be made available in the response body of the token endpoint.

The value of the `request` parameter MUST either be a valid [JWT](https://tools.ietf.org/html/rfc7519) or [JWE](https://tools.ietf.org/html/rfc7516) whose claims are the credential request parameters, however the inner payload MUST be a valid [JWT](https://tools.ietf.org/html/rfc7519) signed by the Client who created the request.

The key used to sign the request object MUST validate to that featured in the `sub_jwk` parameter of the request.

Unsigned plaintext Request Objects, containing `none` in the `alg` value of the JOSE header MUST not be supported.

If the Request Object signing validation fails or is missing, the OpenID Connect Provider MUST respond to the request with the Error Response parameter, [section 3.1.2.6.](https://openid.net/specs/openid-connect-core-1_0.html#AuthError) with Error code: `invalid_request_object`.

If the `did` value is present in the request and the OpenID Provider does not support the usage of [decentralized identifiers](https://w3c.github.io/did-core/) the value should be ignored.

## Request Parameters

A Credential Request uses the OpenID and OAuth2.0 request parameters as outlined in section [3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) of OpenID Connect core, except for the following additional constraints.

scope
: REQUIRED. A Credential Request MUST contain the `openid_credential` scope value in the second position directly after the `openid` scope.

credential_format
: REQUIRED. Determines the format of the credential returned at the end of the flow, values supported by the OpenID Provider are advertised in their openid-configuration metadata, under the `credential_formats_supported` attribute.

sub_jwk
: OPTIONAL. Used when making a Signed Credential Request, defines the key material the client is requesting the credential to be bound to and the key responsible for signing the request object. Value is a JSON Object that is a valid [JWK](https://tools.ietf.org/html/rfc7517).

did
: OPTIONAL. Defines the relationship between the key material the client is requesting the credential to be bound to and a [decentralized identifier](https://w3c.github.io/did-core/). Processing of this value requires the OpenID Provider to support the resolution of [decentralized identifiers](https://w3c.github.io/did-core/) which is advertised in their openid-configuration metadata, under the `dids_supported` attribute. The value of this field MUST be a valid [decentralized identifier](https://w3c.github.io/did-core/).

Public private key pairs are used by a requesting Client to establish a means of binding to the resulting credential. A Client making a Credential Request to an OpenID Provider must prove control over this binding mechanism during the request, this is accomplished through the extended usage of a [signed request](https://openid.net/specs/openid-connect-core-1_0.html#SignedRequestObject) defined in OpenID Connect Core.


## Response Types

It is RECOMMENDED that a Credential Request flow use the [authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps) as defined in OpenID Connect core.

For instances where [implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) is used, the `response_type` of `credential` SHOULD be used.

# Credential Response

## Credential

Formats of the Credential can vary, examples include JSON-LD or JWT based Credentials, the OpenID provider SHOULD make the supported credential formats available at their openid-configuration meta-data endpoint.

The following is a non-normative example of a Credential issued as a [W3C Verifiable Credential 1.0](https://www.w3.org/TR/vc-data-model/) compliant format in JSON-LD.

```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "123456789",
    "jwk": {
      "crv":"secp256k1",
      "kid":"YkDpvGNsch2lFBf6p8u3",
      "kty":"EC",
      "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
      "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
    },
    "givenName": "John",
    "familyName": "Doe",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-10T21:35:35Z",
    "verificationMethod": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..l9d0YHjcFAH2H4dB9xlWFZQLUpixVCWJk0eOt4CXQe1NXKWZwmhmn9OQp6YxX0a2LffegtYESTCJEoGVXLqWAA"
  }
}
```

The following is a non-normative example of a Credential issued as a [JWT](https://tools.ietf.org/html/rfc7519)

```
ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJpc3MiOiAiaXNzdWVyIjogImh0dHBzOi8vaXNzdWVyLmVkdSIsCiAgInN1YiI6ICJkaWQ6ZXhhbXBsZToxMjM0NTYiLAogICJpYXQiOiAxNTkxMDY5MDU2LAogICJleHAiOiAxNTkxMDY5NTU2LAogICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MS9kZWdyZWUiOiB7CiAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxL3R5cGUiOiAiQmFjaGVsb3JEZWdyZWUiLAogICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MS9uYW1lIjogIkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiCiAgfQp9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

And the decoded Claim Set of the JWT

```
{
  "iss": "issuer": "https://issuer.edu",
  "sub": "123456789",
  "sub_jwk" : {
    "crv":"secp256k1",
    "kid":"YkDpvGNsch2lFBf6p8u3",
    "kty":"EC",
    "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
  },
  "iat": 1591069056,
  "exp": 1591069556,
  "https://www.w3.org/2018/credentials/examples/v1/degree": {
     "https://www.w3.org/2018/credentials/examples/v1/type": "BachelorDegree",
     "https://www.w3.org/2018/credentials/examples/v1/name": "Bachelor of Science and Arts"
  }
}
```

## Credential Endpoint

TODO


## Token Endpoint Response (with credential)

If the OpenID Connect request is a Signed Credential Request. The Response from the Token Endpoint MUST include the Credential in the form of an object with value for `format` indicating the credentials format and `data` containing the Credential.

Successful and Error Authentication Response are in the same manor as [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) with the `code` parameter always being returned with the Authorization Code Flow.

On Request to the Token Endpoint the `grant_type` value MUST be `authorization_code` inline with the Authorization Code Flow and the `code` value included as a parameter.

The following is a non-normative example of a response from the token endpoint featuring a JSON-LD based Credential.

```
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
  "token_type": "bearer",
  "expires_in": 86400,
  "id_token": "eyJodHRwOi8vbWF0dHIvdGVuYW50L..3Mz",
  "credential": {
    "format": "w3cvc-jsonld",
    "data": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.gov/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://issuer.edu",
      "issuanceDate": "2020-03-10T04:24:12.164Z",
      "credentialSubject": {
        "id": "123456789",
        "publicKey": {
          "crv":"secp256k1",
          "kid":"YkDpvGNsch2lFBf6p8u3",
          "kty":"EC",
          "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
          "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
        },
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-04-10T21:35:35Z",
        "verificationMethod": "https://issuer.edu/keys/1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..l9d0YHjcFAH2H4dB9xlWFZQLUpixVCWJk0eOt4CXQe1NXKWZwmhmn9OQp6YxX0a2LffegtYESTCJEoGVXLqWAA"
      }
    }
  }
}
```

The following is a non-normative example of a response from the token endpoint featuring a JWT based credential

```
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
  "token_type": "bearer",
  "expires_in": 86400,
  "id_token": "eyJodHRwOi8vbWF0dHIvdGVuYW50L..3Mz",
  "credential": {
    "format": "jwt",
    "data": "ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJpc3MiOiAiaXNzdWVyIjogImh0dHBzOi8vaXNzdWVyLmVkdSIsCiAgInN1YiI6ICJkaWQ6ZXhhbXBsZToxMjM0NTYiLAogICJpYXQiOiAxNTkxMDY5MDU2LAogICJleHAiOiAxNTkxMDY5NTU2LAogICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MS9kZWdyZWUiOiB7CiAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxL3R5cGUiOiAiQmFjaGVsb3JEZWdyZWUiLAogICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MS9uYW1lIjogIkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiCiAgfQp9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
  }
}
```

And the decoded Claim Set of the JWT

```
{
  "iss": "issuer": "https://issuer.edu",
  "sub": "123456789",
  "sub_jwk" : {
    "crv":"secp256k1",
    "kid":"YkDpvGNsch2lFBf6p8u3",
    "kty":"EC",
    "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
  },
  "iat": 1591069056,
  "exp": 1591069556,
  "https://www.w3.org/2018/credentials/examples/v1/degree": {
     "https://www.w3.org/2018/credentials/examples/v1/type": "BachelorDegree",
     "https://www.w3.org/2018/credentials/examples/v1/name": "Bachelor of Science and Arts"
  }
}
```


# Usage of Decentralized Identifiers

[Decentralized identifiers](https://w3c.github.io/did-core/) are a resolvable identifier to a set of statements about the [did subject](https://w3c.github.io/did-core/#dfn-did-subjects) including a set of cryptographic material (e.g public keys). Using this cryptographic material, a [decentralized identifier](https://w3c.github.io/did-core/) can be used as an authenticatable identifier in a credential, rather than using a public key directly. 

## Signed Credential Request using a Decentralized Identifier

A Holder submitting a signed Credential Request can request, that the resulting credential be bound to the Holder through the usage of [decentralized identifiers](https://w3c.github.io/did-core/) by using the `did` field.

A Holder prior to submitting a credential request SHOULD validate that the Credential Provider supports the resolution of decentralized identifiers by retrieving their openid-configuration metadata to check if an attribute of `dids_supported` has a value of `true`.

The Holder SHOULD also validate that the Credential Provider supports the [did method](https://w3c-ccg.github.io/did-method-registry/) to be used in the request by retrieving their openid-configuration metadata to check if an attribute of `did_methods_supported` contains the required did method.

A Credential Provider processing a credential request featuring a [decentralized identifier](https://w3c.github.io/did-core/) MUST follow the following additional steps to validate the request.

1. Validate the value in the `did` field is a valid [decentralized identifier](https://w3c.github.io/did-core/).
2. Resolve this the `did` value to a [did document](https://w3c.github.io/did-core/#dfn-did-documents).
3. Validate that the key in the `sub_jwk` field of the request is referenced in the [authentication](https://w3c.github.io/did-core/#authentication) section of the [DID Document](https://w3c.github.io/did-core/#dfn-did-documents).

If any of the steps fail then the OpenID Provider MUST respond to the request with the Error Response parameter, [section 3.1.2.6.](https://openid.net/specs/openid-connect-core-1_0.html#AuthError) with Error code: `invalid_did`.

The following is a non-normative example of requesting the issuance of a credential that uses a decentralized identifier.

```
{
  "response_type": "code",
  "client_id": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "sub_jwk" : {
    "crv":"secp256k1",
    "kid":"YkDpvGNsch2lFBf6p8u3",
    "kty":"EC",
    "x":"7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    "y":"3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o"
  },
  "did": "did:example:1234",
  "redirect_uri": "https://Client.example.com/callback",
  "credential_format": "w3cvc-jsonld"                                

}
```

The following is a non-normative example of a token endpoint response for the request shown above.

```
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
  "token_type": "bearer",
  "expires_in": 86400,
  "id_token": "eyJodHRwOi8vbWF0dHIvdGVuYW50L..3Mz",
  "credential": {
    "format": "w3cvc-jsonld",
    "data": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.gov/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://issuer.edu",
      "issuanceDate": "2020-03-10T04:24:12.164Z",
      "credentialSubject": {
        "id": "did:example:1234",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-04-10T21:35:35Z",
        "verificationMethod": "https://issuer.edu/keys/1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..l9d0YHjcFAH2H4dB9xlWFZQLUpixVCWJk0eOt4CXQe1NXKWZwmhmn9OQp6YxX0a2LffegtYESTCJEoGVXLqWAA"
      }
    }
  }
}
```

# OpenID Provider Metadata

An OpenID provider can use the following meta-data elements to advertise its support for credential issuance in its openid-configuration defined by [OpenID-Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html).

`credential_supported`
: Boolean value indicating that the OpenID provider supports the credential issuance flow.

`credential_formats_supported`
: A JSON array of strings identifying the resulting format of the credential issued at the end of the flow.

`credential_claims_supported`
: A JSON array of strings identifying the claim names supported within an issued credential. 

`credential_name`
: A human readable string to identify the name of the credential offered by the provider. 

`dids_supported`
: Boolean value indicating that the OpenID provider supports the resolution of [decentralized identifiers](https://w3c.github.io/did-core/).

`did_methods_supported`
: A JSON array of strings representing [Decentralized Identifier Methods](https://w3c-ccg.github.io/did-method-registry/) that the OpenID provider supports resolution of.

The following is a non-normative example of the relevant entries in the openid-configuration meta data for an OpenID Provider supporting the credential issuance flow

```
{
  "dids_supported": true,
  "did_methods_supported": [
    "did:ion:",
    "did:elem:",
    "did:sov:"
  ],
  "credential_supported": true,
  "credential_formats_supported": [
    "w3cvc-jsonld",
    "jwt"
  ],
  "credential_claims_supported": [
    "given_name",
    "last_name",
    "https://www.w3.org/2018/credentials/examples/v1/degree"
  ],
  "credential_name": "University Credential" 
}
```

## URL Construction

In certain instances it is advantageous to be able to construct a URL which points at an OpenID Connect provider, of which is invocable by a supporting OpenID Connect client.

The URL SHOULD use the scheme `openid` to allow supporting clients to register intent to handle the URL.

The URL SHOULD feature the term `discovery` in the host portion of the URL identifying the intent of the URL is to communicate discovery related information.

The URL SHOULD feature a query parameter with key `issuer` who's value corresponds to a valid issuer identifier as defined in [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html). This identifier MUST be a url of the scheme `https://` of which when concatenated with the string `/.well-known/openid-configuration` and dereferenced by an HTTP GET request
results in the retrieval of the providers OpenID Connect Metadata.

The following is a non-normative example of an invocable URL pointing to the OpenID Provider who has the issuer identifier of `https://issuer.example.com`

```
openid://discovery?issuer=https://issuer.example.com
```
