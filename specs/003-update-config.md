# Update Config

Based on fixtures/app.yml and fixtures/sample.yml, please update the config to
support the following changes:

- certs section is raw or resolved config is not needed. please remove it.
- tls is now a struct with fields `ca`, `cert`, `key` in the global section. It's
optional.
- tls in servers is now a boolean field.
- You don't need to resolve the ca/cert/key, just check if the files exists.
