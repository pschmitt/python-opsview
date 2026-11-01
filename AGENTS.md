# Agent notes

This repository contains a Python client for the Opsview REST API.

- Preserve the client API and examples documented in `README.md`.
- There is no CI workflow or test suite in this repository. Use mocked API
  responses for local checks and add regression tests for behavior changes.
- Keep real API credentials and service URLs out of examples and logs.
- Before adding or changing workflows, check for reusable workflows or actions
  in [ci-workflows](https://github.com/pschmitt/ci-workflows) and preserve
  existing caller behavior and check coverage.
