#!/bin/sh
set -e

if [ $# -eq 0 ]; then
  exec ./data/cli/sshdev
else
  exec "$@"
fi