#!/bin/sh
set -e

cd "$(dirname "$0")"

if [ ! -f localhost.pem ] || [ ! -f localhost-key.pem ]; then
  mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1
fi

exec go run . -cert localhost.pem -key localhost-key.pem
