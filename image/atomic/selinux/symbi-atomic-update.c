#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char entrypoint[] = "/usr/libexec/symbi-atomic-update";
static const char controller[] = "/usr/libexec/symbi-atomic-update-controller.py";
static const char expected[] =
    "/run/credentials/o.service/symbi-update-expected.json";
static const char policy[] =
    "/run/credentials/o.service/symbi-update-policy.json";

static int refuse(const char *message) {
    size_t length = strlen(message);
    while (length > 0) {
        ssize_t written = write(STDERR_FILENO, message, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 126;
        message += written;
        length -= (size_t)written;
    }
    return 126;
}

int main(int argc, char **argv) {
    char resolved[sizeof(entrypoint)];
    ssize_t length;
    char *probe_argv[] = {
        "/usr/bin/python3", (char *)controller, "--probe", NULL};
    char *update_argv[] = {
        "/usr/bin/python3", (char *)controller, "--advance",
        (char *)expected, (char *)policy, NULL};
    char *environment[] = {"LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1", NULL};

    if (geteuid() != 0)
        return refuse("Atomic update launcher requires root\n");
    length = readlink("/proc/self/exe", resolved, sizeof(resolved));
    if (length != (ssize_t)(sizeof(entrypoint) - 1) ||
            memcmp(resolved, entrypoint, sizeof(entrypoint) - 1) != 0)
        return refuse("Atomic update launcher path differs\n");
    if (argc == 2 && strcmp(argv[1], "--probe") == 0)
        execve("/usr/bin/python3", probe_argv, environment);
    else if (argc == 4 && strcmp(argv[1], "--advance") == 0 &&
             strcmp(argv[2], expected) == 0 && strcmp(argv[3], policy) == 0)
        execve("/usr/bin/python3", update_argv, environment);
    else
        return refuse("Atomic update launcher arguments differ\n");
    return refuse("Atomic update controller execution failed\n");
}
