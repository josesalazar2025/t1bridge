# Contributing

Use [issues](https://github.com/standardagents/t1bridge/issues) for bugs and
feature requests, and [private reporting](SECURITY.md) for vulnerabilities.
For hardware bugs, include the Mac model identifier, kernel and package
versions, expected behavior, and redacted errors. Never attach serial numbers,
EFI contents, calibration, keybags, biometric data, or Apple binaries.

Read [AGENTS.md](AGENTS.md) before changing code. Keep pull requests focused
and describe how the change was tested. Run focused tests while iterating;
`make quality` is the full source-quality gate. Documentation-only changes
need link, command-syntax, and diff checks, not package rebuilds.

Start with [architecture](docs/architecture.md), the
[Touch ID flow](docs/touch-id.md), and [interfaces](docs/interfaces.md).
Build dependencies are listed in [dependencies](docs/dependencies.md).
Hardware validation is separate from unit tests: follow the
[runbook](docs/hardware-validation.md), preserve password access, and never
erase working enrollments or reset the device as a generic repair step.
