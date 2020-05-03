Client Bound Identity Assertion

%%%
title = "Client Bound Identity Assertion"
abbrev = "Client Bound Identity Assertion"
ipr= ""
area = "Internet"
workgroup = "Working Group"
submissiontype = "IETF"
keyword = [""]
#date = 2020-04-028T00:00:00Z

[seriesInfo]
name = "RFC"
value = "3514"
stream = "IETF"
status = "informational"

[[author]]
initials = "J."
surname = "Thompson"
fullname = "John Thompson"
#role = "editor"
organization = "MATTR Ltd"
  [author.address]
  email = "john.thompson@mattr.global"

[[author]]
initials = "T."
surname = "Looker"
fullname = "Tobias Looker"
#role = "reviewer"
organization = "MATTR Ltd"
  [author.address]
  email = "tobias.looker@mattr.global"

[[author]]
initials = "N."
surname = "Helmy"
fullname = "Nader Helmy"
#role = "reviewer"
organization = "MATTR Ltd"
  [author.address]
  email = "nader.helmy@mattr.global"
%%%

.# Abstract

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

Typically the format of the assertion obtained about the End-User in the OpenID Connect protocol, known as the `id_token` or `user assertion`, is said to be `bearer in nature`, meaning it features no authenticatable binding to the Client that received it. Because of this limitation, OpenID Connect is constrained to an architecture where relying parties must be in direct contact with the issuers/authorities of obtained user assertions in order to trust their presentation.

This specification defines how the OpenID Connect protocol can be extended so that a Client can obtain a user assertion which is bound to the Client in an authenticatable manner. This feature then enables the client to onward disclose the obtained assertion to other relying parties whilst authenticating the established binding, therefore proving it is the rightful possessor of the assertion.


### Table of Contents
 1. Introduction
 2. Scope openid:credential
 3. Client Bound Request Object by Value
 4. Permitted Response Types
 5. Credential Format Paramter
 6. Authorization Request
 7. Credential

{mainmatter}

# Introduction

OpenID Connect 1.0 [OpenID Connect Core 1.0] is a simple identity layer on top of the OAuth 2.0 [@!RFC6749] protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

For a client to bind to an assertion made about their identity, the use of the signed request object is mandatory by the inclusion of a newly defined `openid:credential` scope value. Use of this scope signals to OpenID Connect Providers (OPs) that the Client is requesting a Credential be issued bound to the Client's suject identifier and request claims.

This Credential is made available at the Token endpoint in addition to the Access Token and Id Token.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [@!RFC2119].

In the .txt version of this document, values are quoted to indicate that they are to be taken literally. When using these values in protocol messages, the quotes MUST NOT be used as part of the value. In the HTML version of this document, values to be taken literally are indicated by the use of this fixed-width font.

All uses of JSON Web Signature (JWS) [JWS] and JSON Web Encryption (JWE) [JWE] data structures in this specification utilize the JWS Compact Serialization or the JWE Compact Serialization; the JWS JSON Serialization and the JWE JSON Serialization are not used.

## Terminology

This specification uses the terms defined in OpenID Connect Core 1.0; in addition, the following terms are also defined:

openid:credential
: A scope defined by a Client in the Authorization request to initiate the Client bound identity assertion request.

Credential
: An assertion made about a End-User that has been bound to the requesting Client in an authenticatable manner.


# Scope openid:credential

As part of the Authorization Request, the Client must include the scope `openid:credential` in the second position directly after the scope `openid` to indicate to the OP the Client wants to retrieve a Credential.

Use of the `openid:credential` scope results in the `request` parameter being mandatory in the Authorization request.

Additional scopes may continue to be included resulting in the expected claim values only included in the associated Access Token and Id Tokens. They are ignored for purposes of issuing a client bound Credential.

The following is a non-normative example of an unencoded scope request:

```
scope=openid openid:credential email
```


# Client Bound Request Object by Value

Support for the `request` parameter is MANDATORY for client bound identity assertions.

To bind the Credential claims to the Client making the request, the Request Object must be signed by the Client using a subject identifier and a URI referencing the subject keys included in the `iss` value.

Unsigned plaintext Request Objects, containing `none` in the `alg` value of the JOSE header MUST not be supported.

If the Request Object signing validation fails or is missing, the OpenID Connect Provider MUST respond to the request with the Error Response parameter, [section 3.1.2.6.](https://openid.net/specs/openid-connect-core-1_0.html#AuthError) with Error code: `invalid_request_object`.

A credentials claim is added to the Request Object containing desired claim values, or a reference to them, to be included in the resulting Credential.

A non-normative example of a payload of a signed Request Object signed using a Decentralized Identifier.

```
{
"iss": "did:key:subject-did#key1",
"aud": "https://issuer.example.com",
"response_type": "code",
"client_id": "IAicV0pt9co5nn9D1tUKDCoPQq8BFlGH",
"redirect_uri": "https://client.example.com/callback",
"max_age": 86400,
"claims": 
	{ 
    "id_token": {}, 
    "credential": { 
      "givenName": "Jane",
      "lastName": "Doe",
      "courseId": "foundationTraining"
    }
  }
}
```
  

# Permitted Response Types

Given the Client bound assertion results in an issued Credential that must be retrieved from the Token Endpoint, the `response_type=code` parameter must be used. Additional `response_types` in a "hybrid" flow may be used; `token` and `id_token`; however, this is not recommended if these are to contain personally identifiable information about the subject.

For mobile applications and SPA's it is recommended to follow the use of the [Proof Key Code Exchange (PKCE) by OAuth clients [@!RFC7636] protocol to mitigate authorization code attacks.


# Credential Format Parameter

An additional parameter `credential_format` can OPTIONALLY be included by the Client in the Authorization Request to request a specific format for the Credential, for example `jsonld`.

If the OP does not support a Credential issuance in the format requested
the OP will respond to the Authorization request following OAuth2.0 Error Response Parameters [@!RFC6749] with Error code: `invalid_request`.

If the parameter is omitted, the OP is permitted to default to a Credential format that the Client will receive.

OpenID metadata endpoint should advertise the supported formats for the Credential.  

Non-normative example
`credential_formats_support : [ "jsonld", "jwt" ]`
  
# Authorization Request


A non-normative example of the Authorization request.

```
https://tenant.platform.mattr.global/authorize
?scope=openid%20openid:credential
&code_challenge=DuMlifAQ_thUmJj6HeWfYC-xUvkvAFcpI_4jaelgX1o
&code_challenge_method=S256
&state=h27hjdnk2
&nonce=hajjdjgkf87
&credential_format=jsonld
&request=<signed-jwt-request-obj>
```


# Credential

The Credential is a bound assertion about the client containing claims about the identity of the subject. It is intended to be long-lived and verifiable that the claims were issued to the client by the issuer.

Formats of the Credential can vary, examples include JSON-LD or JWT based Credentials, the OP should make the supported Credential Types available at the OpenID Connect meta data endpoint.

A non-normative example of a Credential issued as a [@!W3C Verifiable Credential 1.0] compliant format in JSON-LD.
```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://issuer.example.org"
  ],
  "id": "https://issuer.example.org/credentials/3732",
  "type": [
    "VerifiableCredential",
    "FoundationTrainingCredential"
  ],
  "issuer": {
    "id": "did:ion:76e12ec712ebc6f1c221ebfeb1f",
    "domain": "example.org"
  },
  "credentialSubject": {
    "id": "did:ion:c48c8af27918117616ea2a4f7f",
    "givenName": "Jane",
    "familyName": "Doe",
    "courseDate": "2020-01-07",
    "courseName": "Foundation Training",
    "expiryDate": "2020-08-07"
  },
  "proof": {}
}
```
{backmatter}




