#!/bin/sh
# Testprojekt-Runner (Linux/macOS/CI): Offline-E2E ohne Netz/Modell.
set -eu
cargo test -p cate-core -p cate-triage -p cate-stages
cargo test -p cate-stages --test testprojekt_e2e
