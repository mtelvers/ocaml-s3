(lang dune 3.0)
(name s3)


(package
 (name s3)
 (synopsis "S3 client for OCaml using Eio")
 (description
  "A minimal Amazon S3 / Ceph RGW compatible client built on Eio and cohttp-eio. Supports streaming uploads and downloads of large objects (single PUT or multipart, auto-selected), object metadata, and AWS Signature Version 4 request signing.")
 (depends
  (ocaml (>= 5.1.0))
  (eio (>= 1.0))
  eio_main
  (cohttp-eio (>= 6.0.0))
  cohttp
  http
  uri
  digestif
  xmlm
  fmt
  logs
  (alcotest :with-test)))
