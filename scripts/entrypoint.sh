#!/bin/sh
set -e

if [ $# -eq 0 ]; then
  exec ./data/cli/dev-sshd
else
  exec "$@"
fi