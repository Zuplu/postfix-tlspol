# Security Policy

## Supported versions

The latest available version is the only supported one. Stay updated to benefit from the latest bug and security fixes.

## Verifying provenance of automated Docker builds

Run the following command to verify the Docker image originated from our open-source GitHub repository:

```
gh attestation verify \
  --repo Zuplu/postfix-tlspol \
  oci://zuplu/postfix-tlspol:latest
```
