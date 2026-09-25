# Changelog

## 0.1.0 - 2026-09-25

First release.

- One fresh sr25519 deposit wallet per payment request (OsRng -> BIP39 -> sr25519), sealed with XChaCha20-Poly1305.
- `Store` trait with SQLite and JSON-file implementations (compare-and-swap versions).
- Finalized-block watcher; detects alpha (`StakeInfoRuntimeApi`) and optionally TAO payments.
- Sweep: fee funding (`TransactionPaymentApi.query_info` + margin + ED), `transfer_stake`, `move_stake` consolidation, `transfer_all` dust return.
- Journal-before-broadcast with mortal (64-block) transactions for restart safety and no double spend.
- `buyback`, `buyback_and_burn`, `buyback_and_recycle`, `buyback_all` via `add_stake_limit` + `burn_alpha` / `recycle_alpha`; automatic buyback per settled payment.
- `buyback` CLI, `http` (axum) and `webhook` (HMAC-SHA256) features.
- Runtime metadata verification of every call/event used.
- Unit tests and an end-to-end localnet test (CI service container).
