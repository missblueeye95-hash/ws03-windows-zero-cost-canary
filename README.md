# WS03 public AppVeyor Windows zero-cost canary

This repository is intentionally generic. It contains only a bounded AppVeyor-hosted Windows capability probe and no private WS03 source, user payloads, credentials, or private artifacts.

Runner output alone cannot authorize promotion. The private WS03 control plane must independently verify that the AppVeyor project is public and eligible for the free open-source plan before provider_ready can become true.
