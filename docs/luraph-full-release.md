# Luraph full-prototype release notes

## Release criteria

This release closes the output scalability issue that appeared on captures with
more than one thousand prototypes. The default writer now emits one streaming
bundle rather than opening one file per prototype.

Validated locally with a synthetic capture matching the large reference scale:

- 1,204 prototypes;
- 127,505 instructions;
- 11 MB generated pseudo-Luau;
- bundle written in under one second on the validation host;
- all package-level release tests passing.

## Included

- `luraph-full` CLI integration;
- sample-local dispatcher recovery tool;
- all-prototype IR validation;
- streaming and atomic output writer;
- optional `--split-protos` compatibility mode;
- safe corpus scanner and structural VM-family fingerprints;
- explicit safety and scope documentation.

## Security boundary

The release does not execute protected payloads. Capture tooling must expose the
parsed prototype tree and return before invoking the payload closure. Do not
commit protected samples, live webhooks, tokens, cookies, hardware identifiers,
or decoded payload output to a public repository.

## Known limitation

This is a dispatcher-free instruction-level devirtualiser, not a guarantee of
original-source reconstruction. A later source-restructuring pass may improve
variable naming and structured `if`/loop output, but it must preserve the
instruction-level output as the auditable ground truth.
