#!/usr/bin/env bash

set -Eeuo pipefail

readonly EXPECTED_SHA256="5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f"
readonly SOURCE_EXECUTABLE="/usr/lib/nmap/nmap"
readonly INSTALL_ROOT="/opt/ti-scale-toolchain/nmap"
readonly DESTINATION_DIRECTORY="${INSTALL_ROOT}/${EXPECTED_SHA256}"
readonly DESTINATION_EXECUTABLE="${DESTINATION_DIRECTORY}/nmap"
readonly SERVICE_USER="ti-scale"

stage_directory=""
installed_this_run=false

fail() {
  printf 'Reviewed nmap installer: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?
  if [[ -n "${stage_directory}" && -d "${stage_directory}" ]]; then
    rm -rf -- "${stage_directory}"
  fi
  if [[ ${status} -ne 0 && "${installed_this_run}" == "true" ]]; then
    rm -f -- "${DESTINATION_EXECUTABLE}"
  fi
}
trap cleanup EXIT

require_root() {
  [[ $(id -u) -eq 0 ]] || fail "run this command as root"
}

require_commands() {
  local command_name
  for command_name in awk getcap id install ln mktemp rm rmdir setpriv sha256sum stat; do
    command -v "${command_name}" >/dev/null 2>&1 \
      || fail "required command is unavailable: ${command_name}"
  done
}

sha256() {
  sha256sum -- "$1" | awk '{print $1}'
}

verify_no_file_capabilities() {
  local capabilities
  capabilities=$(getcap -n -- "$1") \
    || fail "could not inspect Linux file capabilities for $1"
  [[ -z "${capabilities}" ]] \
    || fail "$1 has Linux file capabilities and is incompatible with NoNewPrivileges"
}

verify_source() {
  [[ -f "${SOURCE_EXECUTABLE}" && ! -L "${SOURCE_EXECUTABLE}" ]] \
    || fail "reviewed source must be a regular, non-symlink file: ${SOURCE_EXECUTABLE}"
  [[ $(sha256 "${SOURCE_EXECUTABLE}") == "${EXPECTED_SHA256}" ]] \
    || fail "source SHA-256 does not match the reviewed Nmap 7.99 executable"
}

verify_installed() {
  local identity service_uid service_gid
  [[ -f "${DESTINATION_EXECUTABLE}" && ! -L "${DESTINATION_EXECUTABLE}" ]] \
    || fail "installed executable is missing, linked, or not a regular file"
  [[ $(sha256 "${DESTINATION_EXECUTABLE}") == "${EXPECTED_SHA256}" ]] \
    || fail "installed executable SHA-256 does not match the reviewed binding"
  identity=$(stat -c '%u:%g:%a' -- "${DESTINATION_EXECUTABLE}")
  [[ "${identity}" == "0:0:555" ]] \
    || fail "installed executable must be root:root and mode 0555; observed ${identity}"
  verify_no_file_capabilities "${DESTINATION_EXECUTABLE}"
  service_uid=$(id -u "${SERVICE_USER}") \
    || fail "service user does not exist: ${SERVICE_USER}"
  service_gid=$(id -g "${SERVICE_USER}") \
    || fail "service group does not exist: ${SERVICE_USER}"
  setpriv \
    --reuid="${service_uid}" \
    --regid="${service_gid}" \
    --clear-groups \
    --no-new-privs \
    --inh-caps=-all \
    --ambient-caps=-all \
    --bounding-set=-all \
    "${DESTINATION_EXECUTABLE}" --version >/dev/null \
    || fail "installed executable did not run under the Ti-Scale NoNewPrivileges identity"
}

install_reviewed_executable() {
  verify_source
  install -d -o root -g root -m 0755 -- "${INSTALL_ROOT}" "${DESTINATION_DIRECTORY}"
  if [[ -e "${DESTINATION_EXECUTABLE}" ]]; then
    verify_installed
    printf 'Reviewed nmap executable is already installed and verified: %s\n' "${DESTINATION_EXECUTABLE}"
    return
  fi

  stage_directory=$(mktemp -d "${INSTALL_ROOT}/.nmap-install.XXXXXX")
  install -o root -g root -m 0555 -- "${SOURCE_EXECUTABLE}" "${stage_directory}/nmap"
  [[ $(sha256 "${stage_directory}/nmap") == "${EXPECTED_SHA256}" ]] \
    || fail "staged executable SHA-256 changed during installation"
  verify_no_file_capabilities "${stage_directory}/nmap"

  if ! ln -- "${stage_directory}/nmap" "${DESTINATION_EXECUTABLE}"; then
    [[ -e "${DESTINATION_EXECUTABLE}" ]] \
      || fail "could not atomically publish the reviewed executable"
    verify_installed
    printf 'A concurrent installer published the same verified executable: %s\n' "${DESTINATION_EXECUTABLE}"
    return
  fi
  installed_this_run=true
  verify_installed
  printf 'Installed reviewed capability-free nmap executable: %s\n' "${DESTINATION_EXECUTABLE}"
  printf 'The port-scan binding remains unavailable until an operator enables the reviewed manifest and a fresh activation receipt attests this exact identity.\n'
}

remove_reviewed_executable() {
  [[ ${2:-} == "--confirmed-disabled" ]] \
    || fail "removal requires: remove --confirmed-disabled (disable the binding and drain work first)"
  verify_installed
  rm -- "${DESTINATION_EXECUTABLE}"
  rmdir -- "${DESTINATION_DIRECTORY}" 2>/dev/null || true
  printf 'Removed reviewed nmap executable. The versioned parent and all other tool versions were preserved.\n'
}

main() {
  require_root
  require_commands
  case ${1:-install} in
    install)
      [[ $# -eq 0 || $# -eq 1 ]] || fail "usage: $0 [install|verify|remove --confirmed-disabled]"
      install_reviewed_executable
      ;;
    verify)
      [[ $# -eq 1 ]] || fail "usage: $0 verify"
      verify_installed
      printf 'Reviewed nmap executable passed exact-SHA, ownership, file-capability, and NoNewPrivileges verification.\n'
      ;;
    remove)
      [[ $# -eq 2 ]] || fail "usage: $0 remove --confirmed-disabled"
      remove_reviewed_executable "$@"
      ;;
    *)
      fail "usage: $0 [install|verify|remove --confirmed-disabled]"
      ;;
  esac
}

main "$@"
