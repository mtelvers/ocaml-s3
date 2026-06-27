# s3

A small Amazon S3 / Ceph RGW compatible object-storage client for OCaml,
built on [Eio](https://github.com/ocaml-multicore/eio) and
[cohttp-eio](https://github.com/mirage/ocaml-cohttp).

## Features

- **Large objects.** `put_file` auto-selects between a single `PUT` (small
  files) and a **multipart upload** (large files), sending parts concurrently
  with Eio fibers. Downloads stream straight to a file. Memory use stays
  bounded by the part size × concurrency regardless of object size — a 100 MB
  upload/download round-trip is part of the test suite.
- **Metadata.** Set user metadata (`x-amz-meta-*`) and content type on upload;
  read it back, along with size/ETag/last-modified, via `head_object`.
- **Listing.** `ListObjectsV2` with prefix and pagination: `list_page` (one
  page), `fold_pages` (fold over all pages, following continuation tokens),
  `iter_objects`, and `list_objects` (collect all keys). Entries carry
  `key`, `size`, `etag` and `last_modified`.
- **AWS Signature Version 4.** Every request is signed; the implementation is
  pure and unit-tested against the published AWS test vector.
- **S3-compatible.** Uses path-style addressing by default, as expected by
  Ceph RGW and MinIO.

## API sketch

The library wraps as the `S3` module; the client lives in `S3.Client` and the
signing primitives in `S3.Auth`.

```ocaml
Eio_main.run @@ fun env ->
Eio.Switch.run @@ fun sw ->
let net = Eio.Stdenv.net env and clock = Eio.Stdenv.clock env in
let fs = Eio.Stdenv.fs env in
let credentials =
  (* or S3.Credentials.default_chain () — see below *)
  { S3.Credentials.access_key = "..."; secret_key = "..."; session_token = None }
in
let cfg =
  S3.Client.make_config
    ~endpoint:"http://localhost:9000"   (* RGW / MinIO endpoint *)
    ~credentials ()
in
let s3 = S3.Client.create ~sw ~net ~clock cfg in

(* create a bucket *)
let _ = S3.Client.create_bucket s3 ~bucket:"my-bucket" in

(* upload with metadata; multipart kicks in automatically for large files *)
let _etag =
  S3.Client.put_file s3 ~bucket:"my-bucket" ~key:"big.bin"
    ~content_type:"application/octet-stream"
    ~metadata:[ ("author", "me") ]
    ~path:Eio.Path.(fs / "big.bin") ()
in

(* read metadata *)
(match S3.Client.head_object s3 ~bucket:"my-bucket" ~key:"big.bin" with
 | Ok md -> Printf.printf "size=%d\n" md.S3.Client.content_length
 | Error e -> Format.printf "%a\n" S3.Client.pp_error e);

(* stream back to disk *)
let _ =
  S3.Client.get_to_file s3 ~bucket:"my-bucket" ~key:"big.bin"
    ~path:Eio.Path.(fs / "big.out")
in
()
```

See `lib/client.mli` for the full interface.

## Credentials

`S3.Credentials` resolves credentials the usual AWS way, so a library consumer
doesn't have to hard-code keys:

- `Credentials.from_env ()` — `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
  (and optional `AWS_SESSION_TOKEN`).
- `Credentials.from_profile ?profile ?file ()` — the shared credentials file
  (`~/.aws/credentials`, profile from `AWS_PROFILE` or `default`).
- `Credentials.default_chain ()` — env first, then the profile.

```ocaml
let credentials =
  match S3.Credentials.default_chain () with
  | Ok c -> c
  | Error msg -> failwith msg
in
let cfg = S3.Client.make_config ~endpoint ~credentials () in
```

Temporary credentials are supported: a `session_token` is sent as
`x-amz-security-token` and signed.

## TLS / HTTPS

`https://` endpoints are supported via [ocaml-tls](https://github.com/mirleft/ocaml-tls)
(`tls-eio`). The scheme of the endpoint URL selects the transport, so the same
client handles both `http://` and `https://`.

- Certificate verification defaults to the **operating system trust store**
  (via `ca-certs`). `config.tls_verification` selects the policy:
  `System_trust` (default), `No_verification` (insecure; self-signed/testing),
  or `Ca_file path` (a PEM bundle of trust anchors — e.g. a private RGW CA).
- The TLS stack draws randomness from `mirage-crypto-rng`. `S3.Client.create`
  initialises it for you (once per process, via
  `Mirage_crypto_rng_unix.use_default`, backed by the OS `getrandom`), so no
  caller setup is required.

Validated against live AWS S3 over HTTPS: a ~133 MiB object streamed down
byte-for-byte identically to `curl`, and prefix listings work, with system-trust
certificate verification.

## CLI: `s3cli`

A small command-line front-end (`bin/s3cli.ml`, built with cmdliner) covering
the common operations:

```
s3cli ls   s3://BUCKET[/PREFIX[*]]   # list keys, one per line (follows all pages)
s3cli cp   SRC DST                   # local->s3 upload, s3->local download,
                                     #   or s3->s3 server-side copy (inferred)
s3cli rm   s3://BUCKET/KEY           # delete an object
s3cli stat s3://BUCKET/KEY           # size, ETag, timestamps, user metadata
s3cli mb   s3://BUCKET                # make a bucket
s3cli rb   s3://BUCKET                # remove an (empty) bucket

# ls -l / --long: print "last-modified  size  key" instead of just the key

# cp options (s3 destination only):
#   --part-size SIZE     multipart part size, e.g. 8MiB, 64MB, 1G (default 8MiB)
#   --concurrency N       parts uploaded at once (default 4; also grows the pool)
#   --metadata KEY=VALUE  user metadata (x-amz-meta-KEY); repeatable
```

Connection settings are resolved with this precedence: command-line flag, then
environment variable, then the selected `~/.aws` profile:

| Setting | Flag | Environment | Profile key |
|---|---|---|---|
| Endpoint | `--endpoint-url` | `AWS_ENDPOINT_URL` | `endpoint_url` (config) |
| Region | `--region` | `AWS_REGION` | `region` (config) |
| Access key | `--access-key` | `AWS_ACCESS_KEY_ID` | `aws_access_key_id` |
| Secret key | `--secret-key` | `AWS_SECRET_ACCESS_KEY` | `aws_secret_access_key` |
| Profile | `--profile` | `AWS_PROFILE` | — |
| CA bundle | `--ca-bundle` | `AWS_CA_BUNDLE` | — |
| No TLS verify | `--no-verify` | — | — |
| Anonymous | `--no-sign-request` | — | — |

An empty environment variable is treated as unset (e.g. `AWS_REGION=` falls
through to the profile/default rather than signing with an empty region).
Credentials follow the usual AWS precedence — explicit `--access-key` /
`--secret-key` (which must be given together), else `AWS_*` environment
variables, else the profile's credentials. Because the environment is tried
before the profile, setting `AWS_ACCESS_KEY_ID` while passing `--profile foo`
takes the *endpoint and region* from `foo` but the *credentials* from the
environment.

`--no-sign-request` sends unsigned, anonymous requests (no credentials), for
reading public buckets — the same spelling as aws-cli. It takes precedence over
any supplied or configured credentials, so no `~/.aws` profile or keys are
needed:

```sh
./_build/default/bin/s3cli.exe --no-sign-request \
  --endpoint-url https://s3.amazonaws.com ls s3://1000genomes/
```

> Global options may appear before *or* after the subcommand — both
> `s3cli --endpoint-url … ls s3://…` (s5cmd-style) and
> `s3cli ls --endpoint-url … s3://…` work, as do environment variables.

```sh
day10 build . bin/s3cli.exe

# uses ~/.aws/{credentials,config} just like aws-cli / s5cmd
AWS_PROFILE=ceph-tessera ./_build/default/bin/s3cli.exe \
  ls 's3://tessera-embeddings/v1.1/some_prefix/*' | wc -l

./_build/default/bin/s3cli.exe cp ./big.bin s3://bucket/big.bin
./_build/default/bin/s3cli.exe cp s3://bucket/big.bin ./big.bin
```

### Region redirects

If the endpoint's region doesn't match the bucket's (e.g. pointing the
`us-east-1` endpoint at a `us-west-2` bucket), AWS replies with a redirect and
an `x-amz-bucket-region` header. The client follows it transparently: it
re-points its connection pool at the bucket's regional host, re-signs for that
region, and replays the request (bounded, and cached for subsequent requests).
Hosts it doesn't know how to rewrite (e.g. a custom RGW) surface the original
error instead of looping.

### Server-side copy

`copy_object` (and `s3cli cp s3://… s3://…`) copies via `x-amz-copy-source`, so
the object's bytes are copied by the server and never transit the client (a
133 MiB copy on RGW takes ~1.4s). Source and destination must share an endpoint.

The source is HEADed first for its size: objects ≤ 5 GiB copy in one request;
larger ones use a multipart copy (`UploadPartCopy` over byte ranges,
`part_size`/`max_concurrency` configurable, default 512 MiB × 4). Source
metadata and content type are preserved by default in both paths; pass
`content_type`/`metadata` to replace them.

### Connection pooling

The client keeps a pool of keep-alive connections to the endpoint (bounded by
`config.max_connections`, default 8), reusing them across requests instead of
dialling a fresh connection each time. cohttp-eio has no built-in connection
cache, so the pool hands sockets to cohttp via `Client.make_generic`; cohttp
still does all the HTTP. Connections are recycled once a response body is
consumed, and a request that fails on a *reused* connection is retried once on a
fresh one (to absorb server idle-close). The TLS handshake, for `https`
endpoints, is part of opening a connection and so is amortised across reuse too.

### Retries

Transport failures (timeout, connection/TLS) and transient server responses
(`429`, `500`, `502`, `503` — e.g. RGW/S3 `SlowDown` throttling, common when many
multipart parts upload at once) are retried automatically with exponential
backoff and full jitter, up to 5 times, before the error is returned. Each part
backs off independently, so a throttled multipart upload spreads its retries
rather than failing the whole transfer. Backoff happens between attempts and does
not count against the per-request timeout.

### Comparison with s5cmd

Two workloads on a Ceph RGW, ~1.4M-object bucket.

**Listing** under one prefix (`ListObjectsV2`, inherently sequential — each page
needs the previous page's continuation token, so ~1,400 round-trips):

| | objects | real |
|---|---|---|
| `s5cmd ls` | ~1.40M | 3m54s |
| `s3cli ls` (no pooling) | ~1.40M | 4m18s |
| `s3cli ls` (pooled) | ~1.40M | **3m25s** |

Pooling collapses ~1,400 fresh connections into one reused keep-alive
connection, cutting ~20% off and pulling ahead of s5cmd. This latency-bound,
many-small-requests workload is where reuse pays off. (`s3cli` also uses far
less CPU — it is network-bound where s5cmd burns minutes of CPU.)

**Upload** of a 1 GiB file (multipart). With matched tuning
(`s3cli cp --part-size 64MB --concurrency 8`), interleaved runs against the
(shared, contended) RGW:

| round | `s3cli` (64 MB×8) | `s5cmd` |
|---|---|---|
| 1 | 74s | 44s |
| 2 | 42s | 57s |

The two trade places, and the within-tool variance (s3cli 42–74s, s5cmd 44–57s)
swamps any systematic difference: tuned `s3cli` is **on par with s5cmd** for
upload. Unlike listing, upload throughput is bound by concurrent-stream
bandwidth, not connection setup, so connection reuse does not move it — the
levers are **part size** and **concurrency** (the `--part-size`/`--concurrency`
flags above; `max_connections` grows automatically to admit the concurrency).
The default 8 MiB × 4 is conservative for a fast link; raise both to push
throughput.

(Object counts in the listing table differ slightly between runs due to live
churn in the bucket.)

## Building

This project uses [day10](https://github.com/mtelvers/day10) as a drop-in for
dune/opam:

```sh
day10 build .                       # build the library
day10 build --with-test . @runtest  # run the offline unit tests
```

(Plain dune works too if you have an opam switch with the dependencies.)

## Testing

There are two suites:

- **Unit tests** (`test/test_unit.ml`) — offline. SigV4 known-answer test,
  percent-encoding, and XML parsing. These run under `@runtest`.
- **Integration tests** (`test/test_integration.ml`) — exercise the full client
  against a live S3-compatible server, including a 100 MB multipart round-trip
  verified by SHA-256. They are skipped unless `S3_ENDPOINT` is set, so they
  never block the offline build.

The easiest way to run the integration tests is the helper script, which spins
up a throwaway MinIO in Docker and runs the test binary on the host:

```sh
scripts/run-integration-tests.sh          # 100 MB large-object test
scripts/run-integration-tests.sh 8        # smaller/faster
```

To point at your own server (e.g. a Ceph RGW), build the binary and set the
environment yourself:

```sh
day10 build --with-test . test/test_integration.exe
S3_ENDPOINT=https://rgw.example.com \
S3_ACCESS_KEY=... S3_SECRET_KEY=... S3_REGION=us-east-1 \
  ./_build/default/test/test_integration.exe
```

> The integration binary is run **directly on the host** rather than inside the
> day10 build container, so that `localhost`-style endpoints resolve to the
> machine the server is running on.
