# OpenID Connect Credential Provider

[Latest Draft](https://mattrglobal.github.io/oidc-client-bound-assertions-spec/)

**Previous versions**

[v0.1](https://mattrglobal.github.io/oidc-client-bound-assertions-spec/v0.1)

This repository is the home to the draft specification to extend an OpenID Connect Provider to support the issuance of credentials which in turn enable new approaches around federated sharing of identity information.

## Contributing

The main specification is written in the markdown, however to preview the changes you have made in the final format, the following steps can be followed.

The tool `markdown2rfc` is used to convert the raw markdown representation to both an HTML and XML format. In order to run this tool you must have [docker](https://www.docker.com/) installed.

### Updating Docs

Update `spec.md` file with your desired changes.

Run the following to compile the new txt into the output HTML and XML.

`./scripts/build-html.sh`
