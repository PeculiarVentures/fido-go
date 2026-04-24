# Download FIDO Specs

This development-only command refreshes the local HTML copies under `docs/raw/fido`.

Run it from its module directory:

```sh
cd tools/download_fido_specs
go run .
```

Keeping the downloader in its own nested module keeps it out of the root `go test ./...` and `go list ./...` package set while still allowing normal editor/package resolution.
