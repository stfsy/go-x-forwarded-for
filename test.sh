#!/bin/bash

set -euo pipefail

go test -v -race -cover -timeout 60s ./...
