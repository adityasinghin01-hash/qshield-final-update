# Offline CycloneDX validation resources

The schema set is vendored from the CycloneDX specification's `1.6` release:

- https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json
- https://github.com/CycloneDX/specification/blob/1.6/schema/spdx.schema.json
- https://github.com/CycloneDX/specification/blob/1.6/schema/jsf-0.82.schema.json

The two subsidiary resources retain their upstream content and identifiers.
JSF's licensing attribution is included in that schema's `$comment`.
Validation uses an offline allowlist and does not retrieve unknown references.
Install `requirements-dev.txt` to enable formal validation and the CI check.
