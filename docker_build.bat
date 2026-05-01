@echo off
docker run --rm ^
  -v "%cd%:/src" ^
  -w /src ^
  debian:bookworm ^
  bash -c "apt-get update -qq && apt-get install -y -qq gcc make libcurl4-openssl-dev libssl-dev libcjson-dev && make"
