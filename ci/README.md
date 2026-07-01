# `ci/` — historical staging dir (CI is now live)

The GitHub Actions workflows are **already active** under
[`.github/workflows/`](../.github/workflows/):

- `build.yml` — builds the per-board Suicide bundles (`bootloader.bin` / `partitions.bin` /
  `boot_app0.bin` / `app.bin`) the headless flasher downloads.
- `build-release.yml` — packages the host provisioner for releases.

`build.yml` originally lived **here** (rather than under `.github/workflows/`) because the token
used for the initial push lacked the `workflow` OAuth scope. That scope has since been granted and
the workflow moved into place, so the old `ci/build.yml` copy — which had become a byte-identical
(EOL-only) duplicate of the active one — was removed to prevent drift. The canonical workflow is
now [`.github/workflows/build.yml`](../.github/workflows/build.yml); edit that one.

CI builds are always `SUICIDE_SAFE_MODE` and never a live-`brick` build (see
`docs/SPIKE-PLAN.md` and `docs/SAFETY.md`).
