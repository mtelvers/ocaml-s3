(lang dune 3.0)
(name s3)
(generate_opam_files true)

(license MIT)
(authors "mark.elvers@tunbury.org")
(maintainers "mark.elvers@tunbury.org")

(package
 (name s3)
 (synopsis "S3 client for OCaml using Eio")
 (description
  "A minimal Amazon S3 / Ceph RGW compatible client built on Eio and cohttp-eio. Supports streaming uploads and downloads of large objects (single PUT or multipart, auto-selected), object metadata, and AWS Signature Version 4 request signing.")
 (depends
  (ocaml (>= 5.1.0))
  (eio (>= 1.0))
  (cohttp-eio (>= 6.0.0))
  cohttp
  http
  uri
  digestif
  xmlm
  fmt
  logs
  (tls-eio (>= 0.17.0))
  ca-certs
  x509
  domain-name
  ptime
  mirage-crypto-rng
  (eio_main :with-test)
  (alcotest :with-test)))

(package
 (name s3cli)
 (synopsis "Command-line S3 / Ceph RGW client")
 (description
  "s3cli is a small command-line front-end to the s3 library: paginated listing, upload/download/server-side copy, delete, stat and bucket create/remove. Connection settings are resolved from command-line flags, environment variables, or an AWS-style ~/.aws profile.")
 (depends
  (ocaml (>= 5.1.0))
  (s3 (= :version))
  (cmdliner (>= 1.1.0))
  (eio (>= 1.0))
  eio_main
  fmt))
