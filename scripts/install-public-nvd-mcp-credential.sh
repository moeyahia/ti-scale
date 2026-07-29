#!/usr/bin/env bash

set -euo pipefail
umask 077

credential_directory="/etc/ti-scale-mcp-nvd"
rotate="false"

usage() {
  cat <<'USAGE'
Usage: install-public-nvd-mcp-credential.sh [--directory ABSOLUTE_PATH] [--rotate]

Generate and atomically install a 256-bit bearer credential without displaying it.

  --directory PATH  Dedicated credential directory (default: /etc/ti-scale-mcp-nvd)
  --rotate          Replace an existing credential instead of refusing
  --help            Show this help
USAGE
}

fail() {
  printf 'Credential installation failed: %s\n' "$1" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --directory)
      (($# >= 2)) || fail "--directory requires a value"
      credential_directory="$2"
      shift 2
      ;;
    --rotate)
      rotate="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

((EUID == 0)) || fail "run this helper as root"
[[ "$credential_directory" == /* ]] || fail "the credential directory must be absolute"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v realpath >/dev/null 2>&1 || fail "realpath is required"

git_probe="$(realpath -s -m -- "$credential_directory")"
while [[ "$git_probe" != "/" ]]; do
  if [[ -e "$git_probe/.git" ]]; then
    fail "refusing to place a bearer credential inside a Git working tree"
  fi
  git_probe="$(dirname -- "$git_probe")"
done

if [[ -L "$credential_directory" ]]; then
  fail "the credential directory must not be a symbolic link"
fi

if [[ ! -e "$credential_directory" ]]; then
  install -d -o root -g root -m 0700 -- "$credential_directory"
fi
[[ -d "$credential_directory" ]] || fail "the credential path is not a directory"

resolved_directory="$(realpath -e -- "$credential_directory")"
lexical_directory="$(realpath -s -m -- "$credential_directory")"
[[ "$resolved_directory" == "$lexical_directory" ]] \
  || fail "the credential directory must not traverse symbolic links"

directory_uid="$(stat -c '%u' -- "$resolved_directory")"
directory_mode="$(stat -c '%a' -- "$resolved_directory")"
[[ "$directory_uid" == "0" ]] || fail "the credential directory must be owned by root"
(( (8#$directory_mode & 0077) == 0 )) \
  || fail "the credential directory must not be accessible to group or other users"

destination="$resolved_directory/mcp-token"
if [[ -L "$destination" ]]; then
  fail "the credential destination must not be a symbolic link"
fi
if [[ -e "$destination" ]]; then
  [[ -f "$destination" ]] || fail "the credential destination is not a regular file"
  [[ "$(stat -c '%u' -- "$destination")" == "0" ]] \
    || fail "the existing credential must be owned by root"
  (( (8#$(stat -c '%a' -- "$destination") & 0077) == 0 )) \
    || fail "the existing credential must not be accessible to group or other users"
  [[ "$rotate" == "true" ]] || fail "a credential already exists; use --rotate to replace it"
fi

temporary="$(mktemp --tmpdir="$resolved_directory" .mcp-token.new.XXXXXX)"
cleanup() {
  if [[ -n "${temporary:-}" && -e "$temporary" ]]; then
    rm -f -- "$temporary"
  fi
}
trap cleanup EXIT INT TERM HUP

openssl rand -hex 32 >"$temporary"
chown root:root "$temporary"
chmod 0600 "$temporary"

token_length="$(tr -d '\n' <"$temporary" | wc -c)"
[[ "$token_length" == "64" ]] || fail "openssl produced an unexpected credential length"
LC_ALL=C grep -Eq '^[A-Fa-f0-9]{64}$' "$temporary" \
  || fail "openssl produced an unexpected credential format"

mv -fT -- "$temporary" "$destination"
temporary=""
sync -f "$destination"

printf 'Bearer credential installed securely at %s. Its value was not displayed.\n' "$destination"
printf 'Restart authorized credential consumers during the planned rotation window.\n'
