#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char bridge[] = "/usr/libexec/symbi-bootc-transition";
static const char bootc[] = "/usr/bin/bootc";
static const char install_context[] =
    "system_u:system_r:install_t:s0";
static const char positive_source[] = "/run/symbi-update/source";
static const char negative_source[] = "/run/symbi-update-negative/source";
static const char receipt_prefix[] = "SYMBI_BOOTC_RECEIPT_V1|";

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

static int write_all(int descriptor, const char *value, size_t length) {
    while (length > 0) {
        ssize_t written = write(descriptor, value, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        value += written;
        length -= (size_t)written;
    }
    return 0;
}

static int exact_digest(const char *value) {
    static const char hex[] = "0123456789abcdef";
    size_t index;
    if (strlen(value) != 71 || memcmp(value, "sha256:", 7) != 0)
        return 0;
    for (index = 7; index < 71; index++)
        if (strchr(hex, value[index]) == NULL)
            return 0;
    return 1;
}

static int exact_context(void) {
    char value[sizeof(install_context) + 2];
    int descriptor;
    ssize_t length;
    descriptor = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return 0;
    do {
        length = read(descriptor, value, sizeof(value));
    } while (length < 0 && errno == EINTR);
    if (close(descriptor) != 0 || length < 0)
        return 0;
    if (length > 0 && (value[length - 1] == '\n' || value[length - 1] == '\0'))
        length--;
    return length == (ssize_t)(sizeof(install_context) - 1) &&
        memcmp(value, install_context, sizeof(install_context) - 1) == 0;
}

int main(int argc, char **argv) {
    char resolved[sizeof(bridge)];
    char receipt[256];
    char *end = NULL;
    long parsed_fd;
    struct stat receipt_info;
    ssize_t length;
    int receipt_fd;
    const char *operation;
    const char *digest;
    char *probe_argv[] = {(char *)bootc, "--version", NULL};
    char *negative_argv[] = {
        (char *)bootc, "switch", "--transport", "dir",
        "--enforce-container-sigpolicy", (char *)negative_source, NULL};
    char *positive_argv[] = {
        (char *)bootc, "switch", "--transport", "dir",
        "--enforce-container-sigpolicy", (char *)positive_source, NULL};
    char *rollback_argv[] = {(char *)bootc, "rollback", NULL};
    char **bootc_argv = NULL;
    char *environment[] = {
        "LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL};

    if (geteuid() != 0 || argc != 5 || strcmp(argv[1], "--receipt-fd") != 0)
        return refuse("bootc transition bridge arguments differ\n");
    errno = 0;
    parsed_fd = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || parsed_fd < 3 ||
            parsed_fd > INT_MAX)
        return refuse("bootc transition receipt descriptor differs\n");
    receipt_fd = (int)parsed_fd;
    if (fstat(receipt_fd, &receipt_info) != 0 || !S_ISFIFO(receipt_info.st_mode) ||
            (fcntl(receipt_fd, F_GETFL) & O_ACCMODE) != O_WRONLY)
        return refuse("bootc transition receipt is not a pipe\n");
    operation = argv[3];
    digest = argv[4];
    if (strcmp(operation, "probe") == 0 && strcmp(digest, "-") == 0)
        bootc_argv = probe_argv;
    else if (strcmp(operation, "negative") == 0 && exact_digest(digest))
        bootc_argv = negative_argv;
    else if (strcmp(operation, "positive") == 0 && exact_digest(digest))
        bootc_argv = positive_argv;
    else if (strcmp(operation, "rollback") == 0 && exact_digest(digest))
        bootc_argv = rollback_argv;
    else
        return refuse("bootc transition operation differs\n");
    length = readlink("/proc/self/exe", resolved, sizeof(resolved));
    if (length != (ssize_t)(sizeof(bridge) - 1) ||
            memcmp(resolved, bridge, sizeof(bridge) - 1) != 0)
        return refuse("bootc transition bridge path differs\n");
    if (!exact_context())
        return refuse("bootc transition context differs\n");
    length = snprintf(receipt, sizeof(receipt), "%s%s|%s|%s\n",
                      receipt_prefix, operation, digest, install_context);
    if (length <= 0 || (size_t)length >= sizeof(receipt) ||
            write_all(receipt_fd, receipt, (size_t)length) != 0)
        return refuse("bootc transition receipt failed\n");
    if (fcntl(receipt_fd, F_SETFD, FD_CLOEXEC) != 0)
        return refuse("bootc transition receipt close-on-exec failed\n");
    execve(bootc, bootc_argv, environment);
    return refuse("bootc transition execution failed\n");
}
