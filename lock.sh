#!/bin/sh
# Generate the hash-locked requirements.txt inside the same base image the
# Dockerfile uses, so you don't need pip-tools on the host.
set -eu
docker run --rm -v "$PWD":/w -w /w -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" python:3.12-slim \
  sh -c 'pip install -q pip-tools && pip-compile -q --generate-hashes -o requirements.txt requirements.in && chown "$HOST_UID:$HOST_GID" requirements.txt'
echo "wrote requirements.txt"
