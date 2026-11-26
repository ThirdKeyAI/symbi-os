ARG BASE_IMAGE="ghcr.io/secureblue/sericea-nvidia-hardened@sha256:9b8053d581db16d47b1df18698ffe8cc3f70c45a3758363fdc8d85c1b0fcaf5e"
FROM "${BASE_IMAGE}" AS symbiont-os-nvidia

# This stage is responsible for holding onto
# your config without copying it directly into
# the final image
FROM scratch AS stage-files
WORKDIR /files


# Keys for pre-verified images
# Used to copy the keys into the final image
# and perform an ostree commit.
#
# Currently only holds the current image's
# public key.
FROM scratch AS stage-keys
# Main image
FROM symbiont-os-nvidia
ARG TARGETARCH
ARG RECIPE=/home/runner/work/symbi-os/symbi-os/.cache/assembly-input-evidence/builder/cli/nvidia.json
ARG IMAGE_REGISTRY=ghcr.io/thirdkeyai
ARG BB_BUILD_FEATURES="bootc"
ARG CONFIG_DIRECTORY="/tmp/files"
ARG MODULE_DIRECTORY="/tmp/modules"
ARG IMAGE_NAME="symbiont-os-nvidia"
ARG BASE_IMAGE="ghcr.io/secureblue/sericea-nvidia-hardened"
RUN \
--mount=type=bind,src=.bluebuild-scripts_a654ee88,dst=/scripts/,ro \
  /scripts/pre_build.sh

# Module RUNs
COPY image/overlay/ /
COPY image/vendor/ombuntu/LICENSE /usr/share/licenses/symbiont-os/Ombuntu-MIT
COPY image/vendor/omarchy/LICENSE /usr/share/licenses/symbiont-os/Omarchy-MIT
COPY LICENSE /usr/share/licenses/symbiont-os/Apache-2.0
COPY image/harden-image.sh /tmp/symbi-harden-image.sh
RUN bash /tmp/symbi-harden-image.sh && rm /tmp/symbi-harden-image.sh

RUN \
--mount=type=bind,src=.bluebuild-scripts_a654ee88,dst=/scripts/,ro \
  /scripts/post_build.sh

# Labels are added last since they cause cache misses with buildah
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/blue-build/cli/main/README.md"
LABEL org.blue-build.build-id="89676869-7adb-4aa2-8340-feb0ed72f00f"
LABEL org.opencontainers.image.base.digest="sha256:9b8053d581db16d47b1df18698ffe8cc3f70c45a3758363fdc8d85c1b0fcaf5e"
LABEL org.opencontainers.image.base.name="ghcr.io/secureblue/sericea-nvidia-hardened@sha256:9b8053d581db16d47b1df18698ffe8cc3f70c45a3758363fdc8d85c1b0fcaf5e"
LABEL org.opencontainers.image.created="2026-11-26T03:09:40.383598580+00:00"
LABEL org.opencontainers.image.description="Symbiont Fedora Atomic desktop"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/ThirdKeyAI/symbi-os"
LABEL org.opencontainers.image.title="symbiont-os-nvidia"