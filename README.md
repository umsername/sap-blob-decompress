# sapblob

`sapblob` is a small Go tool and static web demo for decompressing the modern SAP BLOB wrapper variant that stores an 8-byte SAP header, a few padding bits, and a raw DEFLATE payload.

The browser demo is the main public entry point for the project. It lets people try the generator immediately while keeping uploads fully client-side.

## Website-first layout

The main documentation now lives in the static website under `web/`:

- `web/index.html` — online generator
- `web/how-it-works.html` — technical explanation and research lineage
- `web/help.html` — CLI help, install paths, and naming rules
- `web/troubleshooting.html` — common failure modes and sanity checks
- `web/examples.html` — usage examples, publishing steps, and repo hygiene
- `web/install.html` — release downloads, installer scripts, and local install paths

## What the tool does

- reads the SAP wrapper header
- removes the SAP padding bits
- reconstructs the aligned raw DEFLATE stream
- inflates the payload with Go's standard library
- optionally identifies the recovered payload type from magic bytes

## Build and run

```bash
go test ./...
go build ./cmd/sapblob
./web/build.sh
```

## CLI example

```bash
sapblob example.blob
sapblob example.blob --output recovered.pdf
sapblob --identify-type example.blob
```

## Install

Use the website's `Install` page for release downloads, installer scripts, and self-hosting notes.

```bash
go install github.com/umsername/sap-blob-decompress/cmd/sapblob@latest
```

## Default output naming

The recovered payload is not necessarily a PDF. It may be an image, Office document, XML file, ZIP archive, text file, or arbitrary binary data.

By default, the CLI writes the recovered file next to the input and uses best-effort type detection for the extension:

- PDF -> `.pdf`
- JPEG -> `.jpg`
- PNG -> `.png`
- ZIP-like containers -> `.zip`
- XML/HTML -> `.xml`
- JSON -> `.json`
- unknown payload -> `.bin`

Use `--output` to choose the exact output path yourself.

The web page is more ergonomic: when the payload type is recognized from magic bytes, the browser download uses a matching extension such as `.pdf`.

## Public repository hygiene

- do not commit compiled binaries
- do not commit real customer blobs or recovered documents
- prefer neutral sample names such as `example.blob`
- keep public fixtures synthetic or otherwise safely shareable

## License

MIT, for this repository's original code. External research and upstream SAP/MaxDB code remain subject to their own licenses and attribution requirements.
