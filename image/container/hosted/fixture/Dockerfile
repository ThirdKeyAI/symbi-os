# Development fixture for the disposable hosted guest.
# The caller authenticates the root filesystem and selected package candidate.
FROM scratch
ADD ubuntu-base-24.04.5-base-amd64.tar.gz /
COPY packages/ /tmp/offline-packages/
COPY metadata/ /usr/share/symbi-fixture-evidence/metadata/
COPY manifest.json /usr/share/symbi-fixture-evidence/package-manifest.json

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; \
    set -- /tmp/offline-packages/????-*.deb; \
    test "$1" != '/tmp/offline-packages/????-*.deb'; \
    for archive in "$@"; do \
        case "${archive##*/}" in \
            ????-preconfigure-*.deb) \
                dpkg --configure -a ;; \
        esac; \
        dpkg --unpack "$archive"; \
    done; \
    dpkg --configure -a; \
    mkdir -p /usr/local/bin; \
    ln -s /usr/bin/python3 /usr/local/bin/python3; \
    dpkg-query -W -f '${binary:Package}\t${Version}\n' > /usr/share/symbi-fixture-evidence/packages.tsv; \
    rm -rf /tmp/offline-packages; \
    find /usr/share/symbi-fixture-evidence -xdev -type d -exec chmod 0755 {} +; \
    find /usr/share/symbi-fixture-evidence -xdev -type f -exec chmod 0644 {} +

ENV PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
CMD ["/usr/local/bin/python3", "--version"]
