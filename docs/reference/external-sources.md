# External sources, registry and signatures

English · [Русский](external-sources.ru.md)

These features require explicit operator configuration. The inspected package
cannot enable networking or choose trusted keys.

## Bounded external traversal

```sh
scout scan --allow-download --follow-external \
  --external-origin https://raw.githubusercontent.com \
  --external-depth 2 --external-max-requests 16 --external-max-bytes 4194304 \
  --format json -- ./my-plugin
```

Traversal requires both `--follow-external` and `--allow-download`.
Repeat `--external-origin` to replace the default GitHub origins with an exact
allowlist. GitHub repositories require an immutable commit.

Supported literal URLs are captured under `.scout-external/` and scanned through
the normal pipeline. Reports retain source references, hashes and outcomes.
Cycles are deduplicated; failed reads and exhausted quotas remain gaps.
Dynamic URLs and package-manager resolution are outside this traversal.

## MCP Registry

```sh
scout registry fetch --allow-download --name org.example/tool --latest \
  --endpoint https://registry.modelcontextprotocol.io/v0.1/servers \
  --output /ci/registry-current.json
scout registry compare --output /ci/registry-delta.json \
  /ci/registry-previous.json /ci/registry-current.json
scout scan --format json -- /ci/registry-current.json
```

Fetch creates a bounded data snapshot. `--latest` uses the registry's `isLatest`
assertion. Comparison matches name/version identities and rejects incomplete snapshots.
A registry record is not an installation approval.

## DSSE/in-toto verification

```sh
scout verify-attestation --public-key /ci/trusted-signer.pem \
  --envelope ./bundle.oms.sig --artifact ./bundle.zip --subject bundle.zip
```

Verification checks the selected artifact digest and subject against one explicitly
trusted PKIX public key. Supported signatures are Ed25519, P-256 ECDSA and RSA-PSS.
Standalone DSSE and OMS `dsseEnvelope` are supported for in-toto Statement v1/v0.1.

Exit 0 means signature/key/artifact agreement; 1 means a signature or subject mismatch;
2 means malformed input or an operational failure. This does not implement full
Sigstore identity, transparency-log or revocation policy.

## AISOP/AISP and OMS

AISOP/AISP declarations become hashed metadata bound to source bytes.
OMS payloads and selected X.509 claims are extracted as untrusted content.
Parsing a certificate does not verify signer trust.
