#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BROKER_VERSION "2026.07.23-v1"
#define PROTOCOL_VERSION "ti-scale.exact-target-broker.v1"
#define ATTESTATION_SCHEMA "ti-scale.exact-target-sandbox-attestation.v1"
#define BINDING_ID "python3-reviewed-v1"
#ifndef BWRAP_PATH
#define BWRAP_PATH "/usr/bin/bwrap"
#endif
#ifndef PYTHON_PATH
#define PYTHON_PATH "/usr/bin/python3.13"
#endif
#ifndef SYSTEMD_RUN_PATH
#define SYSTEMD_RUN_PATH "/usr/bin/systemd-run"
#endif
#ifndef SYSTEMCTL_PATH
#define SYSTEMCTL_PATH "/usr/bin/systemctl"
#endif
#ifndef MANIFEST_PATH
#define MANIFEST_PATH "/etc/ti-scale/runtime/exact-target-sandbox/activation-manifest.v1.json"
#endif
#ifndef STAGING_ROOT
#define STAGING_ROOT "/var/lib/ti-scale/exploit-sandbox/staging"
#endif
#ifndef JOBS_ROOT
#define JOBS_ROOT "/var/lib/ti-scale/exploit-sandbox/jobs"
#endif
#ifndef RUNTIME_EXECUTIONS_ROOT
#define RUNTIME_EXECUTIONS_ROOT "/run/ti-scale-exact-target-sandbox/executions"
#endif
#ifndef CANCELLATIONS_ROOT
#define CANCELLATIONS_ROOT "/run/ti-scale-exact-target-sandbox/cancellations"
#endif
#define MAX_FRAME 8192
#define MAX_SOURCE_BYTES (1024 * 1024)
#define MAX_TARGETS 8
#define MAX_OUTPUT_BYTES (8 * 1024 * 1024)
#define MAX_TIMEOUT_MS 300000

#ifndef TI_SCALE_SERVICE_USER
#define TI_SCALE_SERVICE_USER "ti-scale"
#endif

static uid_t service_uid;
static gid_t service_gid;

static void json_error(const char *code, const char *message) {
  fprintf(stdout, "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"},\"ok\":false}\n", code, message);
}

static void sha256_buffer(const unsigned char *buffer, size_t length, char output[65]) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (context == NULL
      || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1
      || EVP_DigestUpdate(context, buffer, length) != 1
      || EVP_DigestFinal_ex(context, digest, &digest_length) != 1) {
    if (context != NULL) EVP_MD_CTX_free(context);
    output[0] = '\0';
    return;
  }
  EVP_MD_CTX_free(context);
  for (unsigned int index = 0; index < digest_length; index++) {
    snprintf(output + (index * 2), 3, "%02x", digest[index]);
  }
  output[64] = '\0';
}

static bool sha256_fd(int descriptor, char output[65], off_t *size_out) {
  unsigned char buffer[65536];
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  off_t total = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
    if (context != NULL) EVP_MD_CTX_free(context);
    return false;
  }
  if (lseek(descriptor, 0, SEEK_SET) < 0) {
    EVP_MD_CTX_free(context);
    return false;
  }
  for (;;) {
    ssize_t received = read(descriptor, buffer, sizeof(buffer));
    if (received < 0 && errno == EINTR) continue;
    if (received < 0
        || (received > 0
          && EVP_DigestUpdate(context, buffer, (size_t)received) != 1)) {
      EVP_MD_CTX_free(context);
      return false;
    }
    if (received == 0) break;
    total += received;
  }
  if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1) {
    EVP_MD_CTX_free(context);
    return false;
  }
  EVP_MD_CTX_free(context);
  for (unsigned int index = 0; index < digest_length; index++) {
    snprintf(output + (index * 2), 3, "%02x", digest[index]);
  }
  output[64] = '\0';
  if (size_out != NULL) *size_out = total;
  return lseek(descriptor, 0, SEEK_SET) >= 0;
}

static bool sha256_file(const char *path, char output[65], off_t *size_out) {
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  struct stat metadata;
  bool valid = fstat(descriptor, &metadata) == 0
    && S_ISREG(metadata.st_mode)
    && sha256_fd(descriptor, output, size_out);
  close(descriptor);
  return valid;
}

static bool safe_identifier(const char *value) {
  size_t length = strlen(value);
  if (length < 1 || length > 80 || value[0] == '.' || strstr(value, "..") != NULL) return false;
  for (size_t index = 0; index < length; index++) {
    unsigned char character = (unsigned char)value[index];
    if (!((character >= 'a' && character <= 'z')
      || (character >= 'A' && character <= 'Z')
      || (character >= '0' && character <= '9')
      || character == '.' || character == '_' || character == '-')) return false;
  }
  return true;
}

static bool lowercase_sha256(const char *value) {
  if (strlen(value) != 64) return false;
  for (size_t index = 0; index < 64; index++) {
    if (!((value[index] >= '0' && value[index] <= '9')
      || (value[index] >= 'a' && value[index] <= 'f'))) return false;
  }
  return true;
}

static bool parse_bounded_integer(
  const char *value,
  long minimum,
  long maximum,
  long *result
) {
  if (value == NULL || value[0] == '\0') return false;
  errno = 0;
  char *end = NULL;
  long parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < minimum || parsed > maximum) {
    return false;
  }
  *result = parsed;
  return true;
}

static bool canonical_ip(const char *value) {
  unsigned char address[16];
  char normalized[INET6_ADDRSTRLEN];
  int family = strchr(value, ':') == NULL ? AF_INET : AF_INET6;
  if (inet_pton(family, value, address) != 1
      || inet_ntop(family, address, normalized, sizeof(normalized)) == NULL) return false;
  return strcmp(value, normalized) == 0;
}

static int split_targets(char *csv, char *targets[MAX_TARGETS]) {
  int count = 0;
  char *save = NULL;
  for (char *target = strtok_r(csv, ",", &save);
       target != NULL;
       target = strtok_r(NULL, ",", &save)) {
    if (count >= MAX_TARGETS || !canonical_ip(target)) return -1;
    if (count > 0 && strcmp(targets[count - 1], target) >= 0) return -1;
    targets[count++] = target;
  }
  return count;
}

static int run_wait(char *const arguments[], bool quiet) {
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    if (quiet) {
      int null_descriptor = open("/dev/null", O_RDWR | O_CLOEXEC);
      if (null_descriptor >= 0) {
        dup2(null_descriptor, STDOUT_FILENO);
        dup2(null_descriptor, STDERR_FILENO);
        if (null_descriptor > STDERR_FILENO) close(null_descriptor);
      }
    }
    execv(arguments[0], arguments);
    _exit(127);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return -1;
}

static void iso_time(time_t value, char output[32]) {
  struct tm utc;
  gmtime_r(&value, &utc);
  strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

static void iso_time_timespec(struct timespec value, char output[40]) {
  struct tm utc;
  gmtime_r(&value.tv_sec, &utc);
  size_t length = strftime(output, 40, "%Y-%m-%dT%H:%M:%S", &utc);
  snprintf(
    output + length,
    40 - length,
    ".%03ldZ",
    value.tv_nsec / 1000000L
  );
}

static bool network_probe_variant(bool filtered) {
  char unit[96];
  snprintf(
    unit,
    sizeof(unit),
    "ti-scale-exploit-probe-%s-%ld",
    filtered ? "filtered" : "baseline",
    (long)getpid()
  );
  const char *filtered_program =
    "import socket,sys\n"
    "try:\n"
    " s=socket.create_connection(('127.0.0.1',3132),1);s.close()\n"
    "except OSError: sys.exit(20)\n"
    "try:\n"
    " s=socket.create_connection(('1.1.1.1',443),1);s.close();sys.exit(21)\n"
    "except OSError: sys.exit(0)\n";
  const char *baseline_program =
    "import socket,sys\n"
    "try:\n"
    " s=socket.create_connection(('127.0.0.1',3132),1);s.close()\n"
    " s=socket.create_connection(('1.1.1.1',443),1);s.close()\n"
    "except OSError: sys.exit(20)\n"
    "sys.exit(0)\n";
  char unit_argument[128];
  snprintf(unit_argument, sizeof(unit_argument), "--unit=%s", unit);
  char *arguments[32];
  size_t count = 0;
#define ADD_PROBE_ARGUMENT(value) do { arguments[count++] = (char *)(value); } while (0)
  ADD_PROBE_ARGUMENT(SYSTEMD_RUN_PATH);
  ADD_PROBE_ARGUMENT("--quiet");
  ADD_PROBE_ARGUMENT("--wait");
  ADD_PROBE_ARGUMENT("--collect");
  ADD_PROBE_ARGUMENT(unit_argument);
  ADD_PROBE_ARGUMENT("--property=User=ti-scale");
  ADD_PROBE_ARGUMENT("--property=Group=ti-scale");
  ADD_PROBE_ARGUMENT("--property=NoNewPrivileges=yes");
  ADD_PROBE_ARGUMENT("--property=CapabilityBoundingSet=");
  ADD_PROBE_ARGUMENT("--property=AmbientCapabilities=");
  ADD_PROBE_ARGUMENT("--property=PrivateTmp=yes");
  ADD_PROBE_ARGUMENT("--property=PrivateDevices=yes");
  ADD_PROBE_ARGUMENT("--property=ProtectSystem=strict");
  ADD_PROBE_ARGUMENT("--property=ProtectHome=yes");
  ADD_PROBE_ARGUMENT("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6");
  if (filtered) {
    ADD_PROBE_ARGUMENT("--property=IPAddressDeny=any");
    ADD_PROBE_ARGUMENT("--property=IPAddressAllow=127.0.0.1/32");
  }
  ADD_PROBE_ARGUMENT("--property=RuntimeMaxSec=5s");
  ADD_PROBE_ARGUMENT("--property=MemoryMax=64M");
  ADD_PROBE_ARGUMENT("--property=TasksMax=8");
  ADD_PROBE_ARGUMENT(PYTHON_PATH);
  ADD_PROBE_ARGUMENT("-I");
  ADD_PROBE_ARGUMENT("-B");
  ADD_PROBE_ARGUMENT("-c");
  ADD_PROBE_ARGUMENT(filtered ? filtered_program : baseline_program);
  arguments[count] = NULL;
#undef ADD_PROBE_ARGUMENT
  return run_wait(arguments, true) == 0;
}

static bool network_probe(void) {
  return network_probe_variant(false) && network_probe_variant(true);
}

static void handle_attest(void) {
  char broker_hash[65], manifest_hash[65], bubblewrap_hash[65], interpreter_hash[65];
  char executable_path[128];
  ssize_t executable_length = readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
  if (executable_length < 1 || executable_length >= (ssize_t)sizeof(executable_path)) {
    json_error("attestation_failed", "Cannot resolve confinement broker executable");
    return;
  }
  executable_path[executable_length] = '\0';
  if (!sha256_file(executable_path, broker_hash, NULL)
      || !sha256_file(MANIFEST_PATH, manifest_hash, NULL)
      || !sha256_file(BWRAP_PATH, bubblewrap_hash, NULL)
      || !sha256_file(PYTHON_PATH, interpreter_hash, NULL)) {
    json_error("attestation_failed", "A pinned confinement executable or manifest is unavailable");
    return;
  }
  struct stat cgroup;
  bool cgroup_v2 = stat("/sys/fs/cgroup/cgroup.controllers", &cgroup) == 0
    && S_ISREG(cgroup.st_mode);
  bool probe_ok = cgroup_v2 && network_probe();
  if (!probe_ok) {
    json_error("network_probe_failed", "Exact-target allow and unlisted-address deny probe did not pass");
    return;
  }
  char probe_receipt[65];
  const char *probe_canonical =
    "{\"cgroupV2\":true,\"exactAllowedAddressReached\":true,"
    "\"ipAddressDenyAny\":true,\"unlistedAddressBlocked\":true,"
    "\"unlistedAddressReachableWithoutFilter\":true}";
  sha256_buffer((const unsigned char *)probe_canonical, strlen(probe_canonical), probe_receipt);
  time_t now = time(NULL);
  char observed_at[32], expires_at[32];
  iso_time(now, observed_at);
  iso_time(now + 60, expires_at);
  char canonical[8192];
  int canonical_length = snprintf(
    canonical,
    sizeof(canonical),
    "{\"activationManifestSha256\":\"%s\","
    "\"boundary\":{\"arbitraryEnvironment\":false,\"boundedOutput\":true,"
    "\"boundedRuntime\":true,\"cgroupCancellation\":true,\"credentialTransport\":false,"
    "\"directArgv\":true,\"docker\":false,\"exactTargetEgress\":true,"
    "\"immutableStagedSource\":true,\"kubernetes\":false,\"minimalFilesystem\":\"bubblewrap\","
    "\"networkConfinement\":\"systemd_cgroup_ip_address_allow\",\"platform\":\"linux\","
    "\"publicProvider\":false,\"shell\":false,\"targetPortConfinement\":false},"
    "\"brokerExecutableSha256\":\"%s\",\"brokerVersion\":\"%s\","
    "\"bubblewrapExecutableSha256\":\"%s\",\"expiresAt\":\"%s\","
    "\"grantsMissionExecution\":false,"
    "\"interpreter\":{\"bindingId\":\"%s\",\"executableSha256\":\"%s\",\"language\":\"python\"},"
    "\"observedAt\":\"%s\","
    "\"probe\":{\"cgroupV2\":true,\"exactAllowedAddressReached\":true,"
    "\"ipAddressDenyAny\":true,\"probeReceiptSha256\":\"%s\","
    "\"unlistedAddressBlocked\":true,\"unlistedAddressReachableWithoutFilter\":true},"
    "\"schemaVersion\":\"%s\"}",
    manifest_hash,
    broker_hash,
    BROKER_VERSION,
    bubblewrap_hash,
    expires_at,
    BINDING_ID,
    interpreter_hash,
    observed_at,
    probe_receipt,
    ATTESTATION_SCHEMA
  );
  if (canonical_length < 1 || canonical_length >= (int)sizeof(canonical)) {
    json_error("attestation_failed", "Attestation exceeded its fixed buffer");
    return;
  }
  char receipt_hash[65];
  sha256_buffer((const unsigned char *)canonical, (size_t)canonical_length, receipt_hash);
  fprintf(
    stdout,
    "{\"ok\":true,\"result\":{\"schemaVersion\":\"%s\",\"brokerVersion\":\"%s\","
    "\"brokerExecutableSha256\":\"%s\",\"activationManifestSha256\":\"%s\","
    "\"bubblewrapExecutableSha256\":\"%s\","
    "\"interpreter\":{\"bindingId\":\"%s\",\"language\":\"python\",\"executableSha256\":\"%s\"},"
    "\"boundary\":{\"platform\":\"linux\",\"directArgv\":true,\"shell\":false,"
    "\"immutableStagedSource\":true,\"minimalFilesystem\":\"bubblewrap\","
    "\"networkConfinement\":\"systemd_cgroup_ip_address_allow\",\"exactTargetEgress\":true,"
    "\"targetPortConfinement\":false,\"arbitraryEnvironment\":false,"
    "\"credentialTransport\":false,\"publicProvider\":false,\"boundedOutput\":true,"
    "\"boundedRuntime\":true,\"cgroupCancellation\":true,\"docker\":false,\"kubernetes\":false},"
    "\"probe\":{\"cgroupV2\":true,\"ipAddressDenyAny\":true,"
    "\"exactAllowedAddressReached\":true,\"unlistedAddressReachableWithoutFilter\":true,"
    "\"unlistedAddressBlocked\":true,"
    "\"probeReceiptSha256\":\"%s\"},\"observedAt\":\"%s\",\"expiresAt\":\"%s\","
    "\"grantsMissionExecution\":false,\"receiptSha256\":\"%s\"}}\n",
    ATTESTATION_SCHEMA,
    BROKER_VERSION,
    broker_hash,
    manifest_hash,
    bubblewrap_hash,
    BINDING_ID,
    interpreter_hash,
    probe_receipt,
    observed_at,
    expires_at,
    receipt_hash
  );
}

static bool ensure_directory(
  const char *path,
  mode_t mode,
  uid_t uid,
  gid_t gid,
  bool exclusive
) {
  if (mkdir(path, mode) < 0 && (exclusive || errno != EEXIST)) return false;
  struct stat metadata;
  if (lstat(path, &metadata) < 0
      || !S_ISDIR(metadata.st_mode)
      || S_ISLNK(metadata.st_mode)) return false;
  if (chown(path, uid, gid) < 0 || chmod(path, mode) < 0) return false;
  return true;
}

static bool copy_fd(int source, int destination) {
  unsigned char buffer[65536];
  for (;;) {
    ssize_t received = read(source, buffer, sizeof(buffer));
    if (received < 0 && errno == EINTR) continue;
    if (received < 0) return false;
    if (received == 0) break;
    ssize_t offset = 0;
    while (offset < received) {
      ssize_t written = write(destination, buffer + offset, (size_t)(received - offset));
      if (written < 0 && errno == EINTR) continue;
      if (written < 0) return false;
      offset += written;
    }
  }
  return fsync(destination) == 0;
}

static bool cancellation_requested(const char *execution_id) {
  char marker[512];
  snprintf(marker, sizeof(marker), "%s/%s", CANCELLATIONS_ROOT, execution_id);
  return access(marker, F_OK) == 0;
}

static void remove_cancellation(const char *execution_id) {
  char marker[512];
  snprintf(marker, sizeof(marker), "%s/%s", CANCELLATIONS_ROOT, execution_id);
  unlink(marker);
}

static void handle_cancel(const char *execution_id) {
  if (!safe_identifier(execution_id)) {
    json_error("request_invalid", "Cancellation execution ID is invalid");
    return;
  }
  char marker[512];
  snprintf(marker, sizeof(marker), "%s/%s", CANCELLATIONS_ROOT, execution_id);
  int descriptor = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    json_error("cancellation_failed", "Cancellation marker could not be persisted");
    return;
  }
  close(descriptor);
  char unit[128];
  snprintf(unit, sizeof(unit), "ti-scale-exploit-%s.service", execution_id);
  char *arguments[] = {
    SYSTEMCTL_PATH,
    "stop",
    unit,
    NULL,
  };
  if (run_wait(arguments, true) != 0) {
    json_error(
      "cancellation_failed",
      "Execution unit could not be synchronously stopped"
    );
    return;
  }
  fprintf(
    stdout,
    "{\"ok\":true,\"result\":{\"cancelled\":true,\"executionId\":\"%s\"}}\n",
    execution_id
  );
}

static void handle_execute(
  const char *execution_id,
  const char *expected_source_hash,
  char *targets_csv,
  long timeout_ms,
  long maximum_output_bytes
) {
  char *targets[MAX_TARGETS];
  int target_count = split_targets(targets_csv, targets);
  if (!safe_identifier(execution_id)
      || !lowercase_sha256(expected_source_hash)
      || target_count < 1
      || timeout_ms < 1000 || timeout_ms > MAX_TIMEOUT_MS
      || maximum_output_bytes < 1024 || maximum_output_bytes > MAX_OUTPUT_BYTES) {
    json_error("request_invalid", "Execution request did not pass its fixed bounds");
    return;
  }
  if (cancellation_requested(execution_id)) {
    remove_cancellation(execution_id);
    json_error("cancelled", "Execution was cancelled before launch");
    return;
  }
  int staging_directory = open(STAGING_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (staging_directory < 0) {
    json_error("staging_unavailable", "Private staging root is unavailable");
    return;
  }
  char source_name[96];
  snprintf(source_name, sizeof(source_name), "%s.source", execution_id);
  int source = openat(staging_directory, source_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  close(staging_directory);
  struct stat source_metadata;
  char actual_source_hash[65];
  off_t source_size = 0;
  if (source < 0
      || fstat(source, &source_metadata) < 0
      || !S_ISREG(source_metadata.st_mode)
      || source_metadata.st_uid != service_uid
      || (source_metadata.st_mode & 077) != 0
      || !sha256_fd(source, actual_source_hash, &source_size)
      || source_size < 1 || source_size > MAX_SOURCE_BYTES
      || strcmp(actual_source_hash, expected_source_hash) != 0) {
    if (source >= 0) close(source);
    json_error("source_invalid", "Staged ScriptArtifact identity is invalid");
    return;
  }
  char runtime_directory[512], snapshot_path[1024];
  snprintf(runtime_directory, sizeof(runtime_directory), "%s/%s", RUNTIME_EXECUTIONS_ROOT, execution_id);
  snprintf(snapshot_path, sizeof(snapshot_path), "%s/source.py", runtime_directory);
  if (!ensure_directory(runtime_directory, 0750, 0, service_gid, true)) {
    close(source);
    json_error("duplicate_execution", "Execution runtime directory already exists");
    return;
  }
  int snapshot = open(
    snapshot_path,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0440
  );
  if (snapshot < 0
      || !copy_fd(source, snapshot)
      || fchown(snapshot, 0, service_gid) < 0
      || fchmod(snapshot, 0440) < 0) {
    if (snapshot >= 0) close(snapshot);
    close(source);
    unlink(snapshot_path);
    rmdir(runtime_directory);
    json_error("snapshot_failed", "Immutable ScriptArtifact snapshot could not be staged");
    return;
  }
  close(snapshot);
  close(source);
  char job_path[512], workspace_path[1024], stdout_path[1024], stderr_path[1024];
  snprintf(job_path, sizeof(job_path), "%s/%s", JOBS_ROOT, execution_id);
  snprintf(workspace_path, sizeof(workspace_path), "%s/workspace", job_path);
  snprintf(stdout_path, sizeof(stdout_path), "%s/stdout.log", job_path);
  snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", job_path);
  if (!ensure_directory(job_path, 0710, 0, service_gid, true)
      || !ensure_directory(workspace_path, 0700, service_uid, service_gid, true)) {
    unlink(snapshot_path);
    rmdir(runtime_directory);
    json_error("workspace_failed", "Private execution workspace could not be created");
    return;
  }
  int stdout_descriptor = open(
    stdout_path,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0600
  );
  int stderr_descriptor = open(
    stderr_path,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0600
  );
  if (stdout_descriptor < 0 || stderr_descriptor < 0) {
    if (stdout_descriptor >= 0) close(stdout_descriptor);
    if (stderr_descriptor >= 0) close(stderr_descriptor);
    json_error("output_failed", "Private output files could not be created");
    return;
  }
  close(stdout_descriptor);
  close(stderr_descriptor);
  char unit_name[128], unit_argument[160], timeout_property[64], output_property[64];
  char stdout_property[1200], stderr_property[1200], workspace_property[1200];
  snprintf(unit_name, sizeof(unit_name), "ti-scale-exploit-%s.service", execution_id);
  snprintf(unit_argument, sizeof(unit_argument), "--unit=%s", unit_name);
  snprintf(timeout_property, sizeof(timeout_property), "--property=RuntimeMaxSec=%ldms", timeout_ms);
  snprintf(output_property, sizeof(output_property), "--property=LimitFSIZE=%ld", maximum_output_bytes);
  snprintf(stdout_property, sizeof(stdout_property), "--property=StandardOutput=append:%s", stdout_path);
  snprintf(stderr_property, sizeof(stderr_property), "--property=StandardError=append:%s", stderr_path);
  snprintf(workspace_property, sizeof(workspace_property), "--property=ReadWritePaths=%s", workspace_path);
  char allow_properties[MAX_TARGETS][96];
  char *arguments[128];
  size_t argument_count = 0;
#define ADD_ARGUMENT(value) do { arguments[argument_count++] = (char *)(value); } while (0)
  ADD_ARGUMENT(SYSTEMD_RUN_PATH);
  ADD_ARGUMENT("--quiet");
  ADD_ARGUMENT("--wait");
  ADD_ARGUMENT("--collect");
  ADD_ARGUMENT(unit_argument);
  ADD_ARGUMENT("--property=User=ti-scale");
  ADD_ARGUMENT("--property=Group=ti-scale");
  ADD_ARGUMENT("--property=NoNewPrivileges=yes");
  ADD_ARGUMENT("--property=CapabilityBoundingSet=");
  ADD_ARGUMENT("--property=AmbientCapabilities=");
  ADD_ARGUMENT("--property=PrivateTmp=yes");
  ADD_ARGUMENT("--property=PrivateDevices=yes");
  ADD_ARGUMENT("--property=ProtectSystem=strict");
  ADD_ARGUMENT("--property=ProtectHome=yes");
  ADD_ARGUMENT("--property=ProtectClock=yes");
  ADD_ARGUMENT("--property=ProtectControlGroups=yes");
  ADD_ARGUMENT("--property=ProtectKernelModules=yes");
  ADD_ARGUMENT("--property=RestrictSUIDSGID=yes");
  ADD_ARGUMENT("--property=RestrictRealtime=yes");
  ADD_ARGUMENT("--property=LockPersonality=yes");
  ADD_ARGUMENT("--property=SystemCallArchitectures=native");
  ADD_ARGUMENT("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6");
  ADD_ARGUMENT("--property=IPAddressDeny=any");
  for (int index = 0; index < target_count; index++) {
    const char *suffix = strchr(targets[index], ':') == NULL ? "/32" : "/128";
    snprintf(
      allow_properties[index],
      sizeof(allow_properties[index]),
      "--property=IPAddressAllow=%s%s",
      targets[index],
      suffix
    );
    ADD_ARGUMENT(allow_properties[index]);
  }
  ADD_ARGUMENT("--property=KillMode=control-group");
  ADD_ARGUMENT("--property=TimeoutStopSec=3s");
  ADD_ARGUMENT("--property=MemoryMax=512M");
  ADD_ARGUMENT("--property=TasksMax=64");
  ADD_ARGUMENT("--property=CPUQuota=100%");
  ADD_ARGUMENT("--property=OOMPolicy=kill");
  ADD_ARGUMENT("--property=LimitNOFILE=256");
  ADD_ARGUMENT("--property=UMask=0077");
  ADD_ARGUMENT(timeout_property);
  ADD_ARGUMENT(output_property);
  ADD_ARGUMENT(stdout_property);
  ADD_ARGUMENT(stderr_property);
  ADD_ARGUMENT(workspace_property);
  ADD_ARGUMENT(BWRAP_PATH);
  ADD_ARGUMENT("--die-with-parent");
  ADD_ARGUMENT("--new-session");
  ADD_ARGUMENT("--unshare-all");
  ADD_ARGUMENT("--share-net");
  ADD_ARGUMENT("--unshare-user");
  ADD_ARGUMENT("--disable-userns");
  ADD_ARGUMENT("--clearenv");
  ADD_ARGUMENT("--ro-bind");
  ADD_ARGUMENT("/usr");
  ADD_ARGUMENT("/usr");
  ADD_ARGUMENT("--ro-bind");
  ADD_ARGUMENT("/lib");
  ADD_ARGUMENT("/lib");
  ADD_ARGUMENT("--ro-bind-try");
  ADD_ARGUMENT("/lib64");
  ADD_ARGUMENT("/lib64");
  ADD_ARGUMENT("--proc");
  ADD_ARGUMENT("/proc");
  ADD_ARGUMENT("--dev");
  ADD_ARGUMENT("/dev");
  ADD_ARGUMENT("--tmpfs");
  ADD_ARGUMENT("/tmp");
  ADD_ARGUMENT("--dir");
  ADD_ARGUMENT("/run");
  ADD_ARGUMENT("--ro-bind");
  ADD_ARGUMENT(snapshot_path);
  ADD_ARGUMENT("/run/ti-scale-script.py");
  ADD_ARGUMENT("--bind");
  ADD_ARGUMENT(workspace_path);
  ADD_ARGUMENT("/workspace");
  ADD_ARGUMENT("--chdir");
  ADD_ARGUMENT("/workspace");
  ADD_ARGUMENT("--setenv");
  ADD_ARGUMENT("HOME");
  ADD_ARGUMENT("/workspace");
  ADD_ARGUMENT("--setenv");
  ADD_ARGUMENT("LANG");
  ADD_ARGUMENT("C.UTF-8");
  ADD_ARGUMENT("--setenv");
  ADD_ARGUMENT("LC_ALL");
  ADD_ARGUMENT("C.UTF-8");
  ADD_ARGUMENT("--");
  ADD_ARGUMENT(PYTHON_PATH);
  ADD_ARGUMENT("-I");
  ADD_ARGUMENT("-B");
  ADD_ARGUMENT("/run/ti-scale-script.py");
  for (int index = 0; index < target_count; index++) {
    ADD_ARGUMENT("--target");
    ADD_ARGUMENT(targets[index]);
  }
  arguments[argument_count] = NULL;
#undef ADD_ARGUMENT
  if (argument_count >= 128) {
    json_error("internal_boundary_error", "Execution argv exceeded its compile-time limit");
    return;
  }
  struct timespec started_real, ended_real, started_monotonic, ended_monotonic;
  clock_gettime(CLOCK_REALTIME, &started_real);
  clock_gettime(CLOCK_MONOTONIC, &started_monotonic);
  int status = cancellation_requested(execution_id) ? 143 : run_wait(arguments, true);
  clock_gettime(CLOCK_MONOTONIC, &ended_monotonic);
  clock_gettime(CLOCK_REALTIME, &ended_real);
  long long duration_ms =
    ((long long)ended_monotonic.tv_sec - (long long)started_monotonic.tv_sec) * 1000LL
    + ((long long)ended_monotonic.tv_nsec - (long long)started_monotonic.tv_nsec) / 1000000LL;
  bool cancelled = cancellation_requested(execution_id);
  remove_cancellation(execution_id);
  const char *termination = "failed";
  bool output_truncated = false;
  if (cancelled) termination = "cancelled";
  else if (duration_ms >= timeout_ms) termination = "timed_out";
  else if (status == 153) {
    termination = "output_limit";
    output_truncated = true;
  } else if (status == 0) termination = "exited";
  if (chown(stdout_path, 0, service_gid) < 0
      || chown(stderr_path, 0, service_gid) < 0
      || chmod(stdout_path, 0640) < 0
      || chmod(stderr_path, 0640) < 0) {
    json_error("output_failed", "Execution output could not be sealed for receipt generation");
    return;
  }
  char stdout_hash[65], stderr_hash[65];
  off_t stdout_size = 0, stderr_size = 0;
  if (!sha256_file(stdout_path, stdout_hash, &stdout_size)
      || !sha256_file(stderr_path, stderr_hash, &stderr_size)
      || stdout_size > maximum_output_bytes || stderr_size > maximum_output_bytes) {
    json_error("output_failed", "Execution output failed its bounded receipt check");
    return;
  }
  if (chown(stdout_path, service_uid, service_gid) < 0
      || chown(stderr_path, service_uid, service_gid) < 0
      || chmod(stdout_path, 0600) < 0
      || chmod(stderr_path, 0600) < 0) {
    json_error("output_failed", "Execution output could not be handed to the application");
    return;
  }
  unlink(snapshot_path);
  rmdir(runtime_directory);
  char started_at[40], ended_at[40];
  iso_time_timespec(started_real, started_at);
  iso_time_timespec(ended_real, ended_at);
  int exit_code = status >= 0 && status <= 255 ? status : 255;
  fprintf(
    stdout,
    "{\"ok\":true,\"result\":{\"protocolVersion\":\"%s\",\"executionId\":\"%s\","
    "\"unitName\":\"%s\",\"startedAt\":\"%s\",\"endedAt\":\"%s\","
    "\"exitCode\":%d,\"termination\":\"%s\",\"stdoutSha256\":\"%s\","
    "\"stderrSha256\":\"%s\",\"stdoutBytes\":%lld,\"stderrBytes\":%lld,"
    "\"outputTruncated\":%s}}\n",
    PROTOCOL_VERSION,
    execution_id,
    unit_name,
    started_at,
    ended_at,
    exit_code,
    termination,
    stdout_hash,
    stderr_hash,
    (long long)stdout_size,
    (long long)stderr_size,
    output_truncated ? "true" : "false"
  );
}

static bool peer_is_service_user(void) {
  struct ucred credentials;
  socklen_t length = sizeof(credentials);
  return getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0
    && length == sizeof(credentials)
    && credentials.uid == service_uid;
}

int main(void) {
  struct passwd *service = getpwnam(TI_SCALE_SERVICE_USER);
  if (service == NULL) {
    json_error("service_identity_missing", "Ti-Scale service identity does not exist");
    return 1;
  }
  service_uid = service->pw_uid;
  service_gid = service->pw_gid;
  if (!peer_is_service_user()) {
    json_error("peer_denied", "Only the Ti-Scale service identity may use this boundary");
    return 1;
  }
  char frame[MAX_FRAME + 1];
  ssize_t length = read(STDIN_FILENO, frame, MAX_FRAME);
  if (length < 1 || length > MAX_FRAME) {
    json_error("frame_invalid", "Broker request frame is empty or oversized");
    return 1;
  }
  frame[length] = '\0';
  char *newline = strchr(frame, '\n');
  if (newline != NULL) *newline = '\0';
  if (strchr(frame, '\r') != NULL || (newline != NULL && newline[1] != '\0')) {
    json_error("frame_invalid", "Broker accepts one line per connection");
    return 1;
  }
  char *fields[9] = {0};
  size_t count = 0;
  char *save = NULL;
  for (char *field = strtok_r(frame, "\t", &save);
       field != NULL && count < 9;
       field = strtok_r(NULL, "\t", &save)) {
    fields[count++] = field;
  }
  if (count < 2 || strcmp(fields[1], PROTOCOL_VERSION) != 0) {
    json_error("protocol_invalid", "Unsupported confinement broker protocol");
    return 1;
  }
  if (strcmp(fields[0], "ATTEST") == 0 && count == 2) {
    handle_attest();
    return 0;
  }
  if (strcmp(fields[0], "CANCEL") == 0 && count == 4) {
    handle_cancel(fields[2]);
    return 0;
  }
  long timeout_ms = 0, maximum_output_bytes = 0;
  if (strcmp(fields[0], "EXEC") == 0
      && count == 8
      && strcmp(fields[4], BINDING_ID) == 0
      && parse_bounded_integer(fields[6], 1000, MAX_TIMEOUT_MS, &timeout_ms)
      && parse_bounded_integer(fields[7], 1024, MAX_OUTPUT_BYTES, &maximum_output_bytes)) {
    handle_execute(
      fields[2],
      fields[3],
      fields[5],
      timeout_ms,
      maximum_output_bytes
    );
    return 0;
  }
  json_error("request_invalid", "Broker command shape is invalid");
  return 1;
}
