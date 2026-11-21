# Download statistics

Written once a week by `.github/workflows/stats.yml` on `main`, from public
counters read from outside. TTP itself reports nothing.

| File | Content |
| :--- | :------ |
| `downloads.csv` | Per snapshot: estimated human downloads of the release packages, raw package downloads, stars. |
| `traffic.csv` | Per day: repository views and clones (total and unique), when a token may read them. |
| `downloads.json` | The shields.io endpoint behind the README's download badge. |
| `snapshots/` | Each snapshot in full: per-release floor, raw counts and estimates. |

The estimate subtracts each release's floor of automated downloads (its least
downloaded SBOM, which nobody fetches by hand) from each package's count. See
`scripts/release_stats.py` on `main` for the method and its limits. Referrers
and visited pages are not recorded here: GitHub shows them to maintainers only.
