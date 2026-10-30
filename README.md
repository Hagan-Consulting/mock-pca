# mock-pca

Development-only tooling that imitates the NG9-1-1 PSAP Credentialing Agency (PCA) PKI: a mock PCA root, one or
more Intermediate CAs (ICAs), and Agency, Agent, Element, Service and Signing certificates constructed per the
NG9-1-1 PKI Certificate Policy (CP) v1.3, plus CRLs for revocation testing.

It lets NG9-1-1 software (for example the Service/Agency Locator) be tested against PCA-shaped certificates without
buying production certificates.

> **Not for production.** Certificates and keys made by this tool are for development and testing only. Never add a
> mock PCA root to a production trust bundle.

## Status

Under construction. See the open pull requests and issues.
