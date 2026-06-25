#!/usr/bin/env bash
# Run the S3 integration test suite against a throwaway MinIO server.
#
# MinIO runs in Docker (publishing port 9000 on the host), the test binary is
# built with day10 inside its container, and then — because the binary is
# emitted to the host-visible _build/ via the bind mount — it is executed
# directly on the host so it can reach localhost:9000.
#
# Usage: scripts/run-integration-tests.sh [LARGE_SIZE_MB]   (default 100)
set -euo pipefail

cd "$(dirname "$0")/.."

LARGE_MB="${1:-100}"
CONTAINER=s3-itest-minio
PORT=9000
ENDPOINT="http://localhost:${PORT}"
ACCESS_KEY=minioadmin
SECRET_KEY=minioadmin

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo ">> starting MinIO ($CONTAINER) on $ENDPOINT"
docker run -d --name "$CONTAINER" -p "${PORT}:9000" \
  -e MINIO_ROOT_USER="$ACCESS_KEY" -e MINIO_ROOT_PASSWORD="$SECRET_KEY" \
  minio/minio server /data >/dev/null

echo ">> waiting for MinIO to be ready"
for _ in $(seq 1 30); do
  if curl -s --max-time 2 "$ENDPOINT/minio/health/ready" >/dev/null; then break; fi
  sleep 1
done

echo ">> building test binary with day10"
day10 build --with-test . test/test_integration.exe

echo ">> running integration tests on the host (${LARGE_MB} MiB large-object test)"
S3_ENDPOINT="$ENDPOINT" \
S3_ACCESS_KEY="$ACCESS_KEY" \
S3_SECRET_KEY="$SECRET_KEY" \
S3_LARGE_SIZE_MB="$LARGE_MB" \
  ./_build/default/test/test_integration.exe
