#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#include "magisk.h"

#include "../constants.h"
#include "../utils.h"
#include "common.h"

static const char *const magisk_managers[] = {
  "com.topjohnwu.magisk",
  "io.github.huskydg.magisk"
};

#define SBIN_MAGISK LP_SELECT("/sbin/magisk32", "/sbin/magisk64")
#define BITLESS_SBIN_MAGISK "/sbin/magisk"
#define DEBUG_RAMDISK_MAGISK LP_SELECT("/debug_ramdisk/magisk32", "/debug_ramdisk/magisk64")
#define BITLESS_DEBUG_RAMDISK_MAGISK "/debug_ramdisk/magisk"

/* INFO: Longest path */
static char path_to_magisk[sizeof(DEBUG_RAMDISK_MAGISK)] = { 0 };
static enum magisk_variants magisk_variant = MOfficial;
static bool is_using_sulist = false;

static bool magisk_sqlite(char *restrict output, size_t output_size, const char *const query) {
  const char *const argv[] = { "magisk", "--sqlite", query, NULL };

  if (exec_command(output, output_size, (const char *)path_to_magisk, argv)) return true;

  LOGE("Failed to execute Magisk sqlite query: %s", strerror(errno));

  return false;
}

void magisk_get_existence(struct root_impl_state *state) {
  path_to_magisk[0] = '\0';
  magisk_variant = MOfficial;
  is_using_sulist = false;
  state->variant = (uint8_t)magisk_variant;

  const char *magisk_files[] = {
    SBIN_MAGISK,
    BITLESS_SBIN_MAGISK,
    DEBUG_RAMDISK_MAGISK,
    BITLESS_DEBUG_RAMDISK_MAGISK
  };

  for (size_t i = 0; i < sizeof(magisk_files) / sizeof(magisk_files[0]); i++) {
    if (access(magisk_files[i], F_OK) != 0) continue;

    strcpy(path_to_magisk, magisk_files[i]);

    break;
  }

  if (path_to_magisk[0] == '\0') {
    state->state = Inexistent;

    return;
  }

  /* INFO: Detect Kitsune by capability instead of relying on a version-name
             suffix. Some maintained Kitsune builds use a commit hash as their
             version name, but all of them expose the dedicated sulist table. */
  char has_sulist_table[sizeof("1=1")];
  if (!magisk_sqlite(has_sulist_table, sizeof(has_sulist_table),
                     "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sulist' LIMIT 1")) {
    state->state = Abnormal;

    return;
  }

  if (has_sulist_table[0] != '\0') {
    magisk_variant = MKitsune;
    state->variant = (uint8_t)magisk_variant;

    char sulist_enabled[sizeof("value=1")];
    if (!magisk_sqlite(sulist_enabled, sizeof(sulist_enabled),
                       "SELECT value FROM settings WHERE key='sulist' LIMIT 1")) {
      state->state = Abnormal;

      return;
    }

    is_using_sulist = strcmp(sulist_enabled, "value=1") == 0;
  }

  const char *argv[] = { "magisk", "-V", NULL };

  char magisk_version[32];
  if (!exec_command(magisk_version, sizeof(magisk_version), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    state->state = Abnormal;

    return;
  }

  int minimum_version = magisk_variant == MKitsune ? MIN_KITSUNE_VERSION : MIN_MAGISK_VERSION;
  if (atoi(magisk_version) >= minimum_version) state->state = Supported;
  else state->state = TooOld;
}

bool magisk_uid_granted_root(uid_t uid) {
  char sqlite_cmd[256];
  snprintf(sqlite_cmd, sizeof(sqlite_cmd), "select 1 from policies where uid=%d and policy=2 limit 1", uid);

  const char *const argv[] = { "magisk", "--sqlite", sqlite_cmd, NULL };

  char result[32];
  if (!exec_command(result, sizeof(result), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    return false;
  }

  return result[0] != '\0';
}

bool magisk_uid_should_umount(const char *const process) {
  /* INFO: PROCESS_NAME_MAX_LEN already has a +1 for NULL */
  char sqlite_cmd[59 + PROCESS_NAME_MAX_LEN];
  if (is_using_sulist) {
    /* INFO: SuList is an allowlist. Processes without a matching entry must
               receive the clean namespace. Prefix matching mirrors the
               standard denylist behavior for secondary app processes. */
    snprintf(sqlite_cmd, sizeof(sqlite_cmd),
             "SELECT 1 FROM sulist WHERE \"%s\" LIKE process || '%%' LIMIT 1", process);
  } else {
    /* INFO: Kitsune keeps normal MagiskHide entries in `hidelist`; official
               Magisk uses `denylist`. Find whether the process starts with an
               entry so a package row also covers its secondary processes. */
    const char *table = magisk_variant == MKitsune ? "hidelist" : "denylist";
    snprintf(sqlite_cmd, sizeof(sqlite_cmd),
             "SELECT 1 FROM %s WHERE \"%s\" LIKE process || '%%' LIMIT 1", table, process);
  }

  char result[sizeof("1=1")];
  if (!magisk_sqlite(result, sizeof(result), sqlite_cmd)) {
    /* INFO: In Kitsune, failure to read the allow/hide policy must not expose
               root mounts to a process that should have received a clean
               namespace. Official Magisk retains its established behavior. */
    return magisk_variant == MKitsune;
  }

  return is_using_sulist ? result[0] == '\0' : result[0] != '\0';
}

bool magisk_uid_is_manager(uid_t uid) {
  const char *const argv[] = { "magisk", "--sqlite", "select value from strings where key=\"requester\" limit 1", NULL };

  char output[128];
  if (!exec_command(output, sizeof(output), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    return false;
  }

  if (strncmp(output, "value=", strlen("value=")) == 0 && output[strlen("value=")] != '\0') {
    char stat_path[PATH_MAX];
    snprintf(stat_path, sizeof(stat_path), "/data/user_de/0/%s", output + strlen("value="));

    struct stat st;
    if (stat(stat_path, &st) == -1) {
      if (errno != ENOENT) LOGE("Failed to stat %s: %s", stat_path, strerror(errno));

      return false;
    }

    return st.st_uid == uid;
  }

  /* INFO: requester can be absent before the manager registers itself. Check
             both known package defaults instead of assuming one from the
             Magisk version string. */
  for (size_t i = 0; i < sizeof(magisk_managers) / sizeof(magisk_managers[0]); i++) {
    char stat_path[PATH_MAX];
    snprintf(stat_path, sizeof(stat_path), "/data/user_de/0/%s", magisk_managers[i]);

    struct stat st;
    if (stat(stat_path, &st) == 0) {
      if (st.st_uid == uid) return true;

      continue;
    }
    if (errno != ENOENT) LOGE("Failed to stat %s: %s", stat_path, strerror(errno));
  }

  return false;
}
