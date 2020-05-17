%%%
title = "Client Bound End-User Assertion"
abbrev = "Client Bound End-User Assertion"
ipr = "none"
workgroup = "none"
keyword = [""]
#date = 2020-04-028T00:00:00Z

[seriesInfo]
name = "Individual-Draft"
value = "client-bound-end-user-assertion"
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

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User.

Typically the format of the assertion obtained about the End-User in the OpenID Connect protocol, known as the `id_token` or user assertion, is said to be bearer in nature, meaning it features no authenticatable binding to the Client that requested it. Because of this limitation, OpenID Connect is constrained to an architecture where relying parties must be in direct contact with the issuers/authorities of obtained user assertions in order to trust their presentations.

This specification defines how the OpenID Connect protocol can be extended so that a Client can obtain an assertion about the End-User which is bound to the Client in an authenticatable manner based on public/private key cryptography. This feature then enables the Client to onward present the obtained assertion to other relying parties whilst authenticating the established binding to the assertion.

{mainmatter}

# Introduction {#Introduction}

OpenID Connect 1.0 [OpenID Connect Core 1.0] is a simple identity layer on top of the OAuth 2.0 `@!RFC6749` protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User.

Typically the format of the assertion obtained about the End-User in the OpenID Connect protocol, known as the `id_token` or user assertion, is said to be bearer in nature, meaning it features no authenticatable binding to the Client that requested it. Because of this limitation, OpenID Connect is constrained to an architecture where relying parties must be in direct contact with the issuers/authorities of obtained user assertions in order to trust their presentations.

This specification defines how the OpenID Connect protocol can be extended so that a Client can obtain an assertion about the End-User which is bound to the Client in an authenticatable manner based on public/private key cryptography. This feature then enables the Client to onward present the obtained assertion to other relying parties whilst authenticating the established binding to the assertion.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OpenID ProviderTIONAL" in this document are to be interpreted as described in RFC 2119 `@!RFC2119`.

In the .txt version of this document, values are quoted to indicate that they are to be taken literally. When using these values in protocol messages, the quotes MUST NOT be used as part of the value. In the HTML version of this document, values to be taken literally are indicated by the use of this fixed-width font.

All uses of JSON Web Signature (JWS) [JWS] and JSON Web Encryption (JWE) [JWE] data structures in this specification utilize the JWS Compact Serialization or the JWE Compact Serialization; the JWS JSON Serialization and the JWE JSON Serialization are not used.

## Terminology {#Terminology}

This specification uses the terms defined in OpenID Connect Core 1.0; in addition, the following terms are also defined:

Credential
: An assertion made about an End-User that has been bound in an authenticatable manner through the use of public/private key pairs to the requesting Client.

Credential Request
: An OpenID Connect Authentication Request that results in the End-User being authenticated by the Authorization Server and the Client receiving a credential about the authenticated End-User.

## Overview

This specification extends the OpenID Connect protocol for the purposes of credential issuance.

1. The Client sends a credential request to the OpenID Provider (OpenID Provider).
2. The OpenID Provider authenticates the End-User and obtains authorization.
3. The OpenID Provider responds with a Credential.

These steps are illustrated in the following diagram:

```
+--------+                                   +----------+
|        |                                   |          |
|        |------(1) Credential Request------>|          |
|        |                                   |          |
|        |  +--------+                       |          |
|        |  |        |                       |          |
| Client |  |  End-  |<--(2) AuthN & AuthZ-->|    OP    |
|        |  |  User  |                       |          |
|        |  |        |                       |          |
|        |  +--------+                       |          |
|        |                                   |          |
|        |<-----(3) Credential Response------|          |
|        |                                   |          |
+--------+                                   +----------+
```

# Credential Request 

A credential request is an OpenID Connect authentication request that requests that the End-User be authenticated by the Authorization Server and a credential containing the requested claims about the End-User be issued to the Client.

The following section outlines how an [OpenID Connect Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) must be extended in order for it to be considered a credential request.

## Example

The credential request follows OpenID Connect 1.0 [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) including the required usage of the `request` parameter.

A non-normative example of the Authorization request.

```
https://issuer.example.com/authorize
?scope=openid%20openid:credential
&request=<signed-jwt-request-obj>
```

Where the decoded payload of the request parameter is as follows

```
{
  "iss": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "aud": "https://issuer.example.com",
  "response_type": "code",
  "client_id": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "sub": "did:example:123456",
  "registration": {
     "jwks_uri": "did:example:123456"
  },
  "redirect_uri": "https://client.example.com/callback",
  "credential_format": "w3cvc-jsonld",
  "max_age": 86400,
  "claims": 
	{ 
    "credential": { 
      "given_name": {"essential": true},
      "last_name": {"essential": true},
      "https://www.w3.org/2018/credentials/examples/v1/degree": {"essential": true}
    },
  }
}
```

## Request Parameters

A credential request uses the OpenID and OAuth2.0 request parameters as outlined in section [3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) of OpenID Connect core, except for the following additional constraints.

scope
: REQUIRED. A credential request MUST contain the `openid:credential` scope value in the second position directly after the `openid` scope.

response_type
: REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used, including what parameters are returned from the endpoints used. In a credential request this value MUST be set to `code`, no other values are to be supported.

credential_format
: REQUIRED. Determines the format of the credential returned at the end of the flow, values supported by the OpenID Provider are advertised in their openid-configuration metadata, under the `credential_formats_supported` attribute.

sub
: REQUIRED. Defines the identifier the Client is requesting that the subject be referred to as, in the resulting obtained credential.

## Request Parameter

Usage of the `request` parameter as defined in section [5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) of OpenID Connect core is REQUIRED in a credential request.

The value of the `request` parameter MUST either be a valid JWT or JWE whose claims are the credential request parameters.

Unsigned plaintext Request Objects, containing `none` in the `alg` value of the JOSE header MUST not be supported.

The Request Object MAY also be encrypted using [JWE](https://tools.ietf.org/html/rfc7516), however the inner payload MUST be a valid [JWT](https://tools.ietf.org/html/rfc7519) signed by the Client who created the request.

Public private key pairs are used by a requesting Client to establish a means of binding to the resulting credential. A Client making a credential request to an OpenID Provider must prove control over this binding mechanism during the request, this is accomplished through the use of a [signed request](https://openid.net/specs/openid-connect-core-1_0.html#SignedRequestObject) defined in OpenID Connect Core.

To bind the credential request to the Client making the request, the Request Object MUST be signed by the Client using a public private key pair the Client is in possession of.

If the Request Object signing validation fails or is missing, the OpenID Connect Provider MUST respond to the request with the Error Response parameter, [section 3.1.2.6.](https://openid.net/specs/openid-connect-core-1_0.html#AuthError) with Error code: `invalid_request_object`.

## Response Types

A credential request flow MUST use the [authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps) as defined in OpenID Connect core.

Given that a credential request flow, results in a credential that MUST be retrieved from the Token Endpoint, the `response_type=code` parameter MUST be used. Additional `response_types` in a "hybrid" flow MAY be used; `token` and `id_token`; however, this is NOT recommended if these are to contain personally identifiable information about the subject.

For mobile applications and SPA's it is RECOMMENDED to follow the use of the [Proof Key Code Exchange (PKCE) by OAuth Clients `@!RFC7636` protocol.

## Requesting a credential using the credential request parameter

A non-normative example of a payload of a signed Request Object.

```
{
  "iss": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "aud": "https://issuer.example.com",
  "response_type": "code",
  "Client_id": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
  "sub": "did:example:123456",
  "redirect_uri": "https://Client.example.com/callback",
  "credential_format": "w3cvc-jsonld",
  "max_age": 86400,
  "claims": 
	{ 
    "credential": { 
      "given_name": {"essential": true},
      "last_name": {"essential": true},
      "https://www.w3.org/2018/credentials/examples/v1/degree": {"essential": true}
    },
  }
}
```

# Credential Response

## Credential

A Credential is a Client bound assertion describing the End-User authenticated in an OpenID flow. Formats of the Credential can vary, examples include JSON-LD or JWT based Credentials, the OpenID provider should make the supported credential formats available at their openid-configuration meta-data endpoint.

The following is a non-normative example of a Credential issued as a `@!W3C Verifiable Credential 1.0` compliant format in JSON-LD.

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
    "id": "did:example:123456",
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

## Token Endpoint Response

Successful and Error Authentication Response are in the same manor as OpenID Connect 1.0 [OpenID Connect Core 1.0] with the `code` parameter always being returned with the Authorization Code Flow.

On Request to the Token Endpoint the `grant_type` value MUST be `authorization_code` inline with the Authorization Code Flow and the `code` value included as a parameter.

The Response from the Token Endpoint MUST include the Credential in the form of an object with value for `format` indicating the credentials format and `data` containing the Credential.

The following is a non-normative example of a JSON-LD based Credential.

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
      "issuer": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
      "issuanceDate": "2020-03-10T04:24:12.164Z",
      "credentialSubject": {
        "id": "did:example:123456",
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
	}
}
```

# Credential Offer

The openid-configuration for an OpenID provider is used to communicate to Clients what capabilities the provider supports, including whether or not it supports the credential issuance flow. Sometime it is desirable to be able to embedded a link to an offer that is invocable by supported Clients.


The following is a non-normative example of a invocable URL pointing to a credential offer offered by the OpenID Provider `issuer.example.com`

```
openid://offer?https://issuer.example.com/.well-known/openid-configuration#/credential_offers[0]
```

# OpenID Provider Metadata

An OpenID provider can use the following meta-data elements to advertise its support for credential issuance in its openid-configuration defined by [OpenID-Discovery].

`credential_supported`
: Boolean value indicating that the OpenID provider supports the credential issuance flow.

`credential_formats_supported`
: A JSON array of strings identifying the resulting format of the credential issued at the end of the flow.

`credential_offers`
: A JSON array of objects, each of which describing a group of related claims that can be referred to when interacting with the OpenID provider.

The following is a non-normative example of the relevant entries in the openid-configuration meta data for an OpenID Provider supporting the credential issuance flow

```
{
  "credential_supported": true,
  "credential_formats_supported": [
    "w3cvc-jsonld",
    "jwt"
  ],
  "credential_offers": [
    {
      "id": "7234f6dd-ec4f-4814-b30b-ab91187e8648",
      "claims": [ 
        "given_name",
        "last_name",
        "https://www.w3.org/2018/credentials/examples/v1/degree"
      ]
    }
  ]
}
```
