# ldap_jwt_sso
A simple [single sign-on (SSO)](https://en.wikipedia.org/wiki/Single_sign-on) implementation using LDAP login and [JSON Web Tokens](https://jwt.io/) implemented using [Apache2](https://httpd.apache.org/) [mod_perl](https://perl.apache.org/).

It runs as a Docker container (so Dockerfile included). You will also need a TLS certificate for this to work (configure in the Makefile). Modify config.txt to fit your own LDAP and network params (note also, config_AD.txt is an example showing settings that should work with an Active Directory server). Once you have it running, navigate to the root of the running server to see an index.html page that lists the various URLS you can use (to login to get a token, validate a token, and redirect-on-validate a token) to interact with the SSO service.

A Makefile is included to build and run (but you will need to modify it with your own values for AWS credentials, etc.) E.g.

`make build`\
`make run`\
etc.
