# S3 Container-Stufe: PoC-Runner-Image (Linux only).
#
# Pinning: Tag + Digest (Manifestliste, 2026-10-15 via registry-1.docker.io
# verifiziert). Tag allein waere mutabel; Digest macht den Build reproduzierbar.
# Erneuern: Digest rechts mit dem aktuellen 3.21-Manifest-Digest ersetzen
# (siehe ci/sandbox/README.md, "Image-Pinning").
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

# HINWEIS (Hadolint DL3008): curl bewusst ohne Versionspin — das Basis-Image
# ist per Digest gepinnt, daher ist der apk-Index deterministisch. Ein zusaetzlicher
# Versionspin wuerde den Build bei jedem Patch-Release brechen, ohne mehr zu bringen.
# curl ist Absicht: N2 (Egress-Test) braucht ein Netz-Tool, damit der Negativ-Test
# ueberhaupt scheitern *koennte* — ohne Tool waere N2 trivial-fein (falsches Gefuehl).
# bash ist Absicht: N3 faehrt die klassische Fork-Bombe `:(){ :|:& };:`,
# die busybox-ash nicht ausdruecken kann.
RUN apk add --no-cache curl bash \
    && rm -rf /var/cache/apk/*

# Non-root Default (wird von run.sh zusaetzlich mit --user erzwungen).
RUN adduser -D -u 65532 -h /nonexistent -s /sbin/nologin poc
USER 65532:65532
WORKDIR /work

# Kein ENTRYPOINT/CMD mit impliziter Shell: der Runner uebergibt argv direkt.
CMD ["/bin/sh"]
