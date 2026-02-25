#!/usr/bin/env bash
set -euo pipefail

if ! command -v h2spec >/dev/null 2>&1; then
  echo "h2spec not found in PATH" >&2
  exit 1
fi
if ! command -v nghttpd >/dev/null 2>&1; then
  echo "nghttpd not found in PATH" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found in PATH" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" >/dev/null 2>&1; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cert_file="$tmp_dir/cert.pem"
key_file="$tmp_dir/key.pem"
doc_root="$tmp_dir/www"
mkdir -p "$doc_root"
printf 'ok\n' >"$doc_root/index.html"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$key_file" \
  -out "$cert_file" \
  -days 1 \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1

h2_port="${SOTH_MITM_H2SPEC_PORT:-9443}"
nghttpd --no-tls-proto=http/1.1 -d "$doc_root" "$h2_port" "$key_file" "$cert_file" \
  >"$tmp_dir/nghttpd.log" 2>&1 &
server_pid="$!"

for _ in $(seq 1 50); do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    echo "nghttpd exited before readiness" >&2
    cat "$tmp_dir/nghttpd.log" >&2 || true
    exit 1
  fi
  if openssl s_client -alpn h2 -connect "127.0.0.1:${h2_port}" -servername 127.0.0.1 \
    </dev/null >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

h2spec \
  -h 127.0.0.1 \
  -p "$h2_port" \
  -k \
  -t
