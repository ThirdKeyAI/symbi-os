# Development fixture for the disposable Ubuntu guest, not a Symbiont OS base.
# Authenticate this archive against the retained, signed Ubuntu checksums first.
FROM scratch
ADD ubuntu-base-24.04.5-base-amd64.tar.gz /

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get -o Acquire::Retries=2 update; \
    apt-get --yes --no-install-recommends install python3 git ca-certificates; \
    mkdir -p /usr/local/bin /usr/share/symbi-fixture-evidence/apt; \
    ln -s /usr/bin/python3 /usr/local/bin/python3; \
    dpkg-query -W -f '${binary:Package}\t${Version}\n' > /usr/share/symbi-fixture-evidence/packages.tsv; \
    apt-cache policy python3 git ca-certificates > /usr/share/symbi-fixture-evidence/package-origins.txt; \
    cp /var/lib/apt/lists/*_InRelease /usr/share/symbi-fixture-evidence/apt/; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
CMD ["/usr/local/bin/python3", "--version"]
