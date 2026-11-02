# Security policy

mock-pca produces **test** credentials for NG9-1-1 software. It is not a production PKI: private keys are stored
unencrypted, and none of the CP's key-protection, ceremony or audit requirements are imitated.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on the repository's **Security** tab, choose **Report a
vulnerability** (GitHub private vulnerability reporting). Do not open a public issue.

Please include the affected version or commit, how to reproduce the problem, and its impact. We aim to acknowledge a
report within 5 business days and will keep you informed while we work on a fix.

## Supported versions

Only the latest release, and `main`, receive security fixes.

## Scope

In scope, for example:

- `mockpca-serve`: crashes, path traversal, resource exhaustion or other misbehaviour caused by HTTP or OCSP requests.
- `bin/mockpca`: command or configuration injection through its inputs, or files written outside the PKI directory.
- `mockpca-lint` false negatives: a certificate that violates a CP v1.3 SHALL/MUST requirement but passes the linter,
  so that the tool issues it. (A disputed reading of unclear CP text is a normal issue, not a vulnerability.)
- Generated material that could be mistaken for, or chain to, a production PCA certificate.

Out of scope (by design; see [docs/DESIGN.md](docs/DESIGN.md#security-notes)):

- Unencrypted private keys, missing HSM support, and other absent production key-protection controls.
- Using mock-pca, or trusting its mock root, in production.
- Fault-injection features (`mockpca ocsp-fault`) and negative test fixtures behaving as documented.
