# WS03 public GitHub Windows GUI v2 canary

This repository payload is intentionally generic and public-safe. It contains no private WS03 source, credentials, user payloads, or private artifacts.

The v2 probe fails closed unless a GitHub-hosted Windows job proves an interactive input desktop, UI Automation discovery, non-uniform screenshot capture, real Win32 `SendInput` keyboard delivery with textbox readback, and a real Win32 `SendInput` mouse click whose button event is independently observed both in application UI state and a runner-local receipt file.

A successful workflow alone is not sufficient for WS03 promotion. The private control plane must independently verify repository visibility, workflow/probe hashes, expected public runner selection, and the emitted `WS03_CANARY_JSON`.
