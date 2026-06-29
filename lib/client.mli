(** An S3 / Ceph RGW object-storage client built on Eio.

    The client speaks the S3 REST API over HTTP using {!Cohttp_eio} and signs
    every request with AWS Signature Version 4 (see {!module:Auth}). It targets
    S3-compatible servers — it has been developed against Ceph RGW and MinIO —
    and uses {e path-style} addressing by default, which those servers expect.

    All operations stream: downloads are copied to their destination chunk by
    chunk, and uploads larger than a threshold are split into a multipart upload
    whose parts are sent concurrently, so memory use stays bounded regardless of
    object size. *)

(** How to verify the server's TLS certificate for [https://] endpoints. *)
type tls_verification =
  | System_trust  (** Verify against the operating system's trust store. *)
  | No_verification
      (** Accept any certificate. Insecure — for testing against servers with
          self-signed certificates only. *)
  | Ca_file of string
      (** Verify against the PEM-encoded trust anchors in this file. *)

(** Connection and credential configuration. *)
type config = {
  endpoint : string;
      (** Base URL of the server, e.g. ["http://localhost:9000"] or
          ["https://s3.example.com"]. Both [http] and [https] are supported;
          the scheme selects whether TLS is used. *)
  region : string;  (** Signing region, e.g. ["us-east-1"]. *)
  credentials : Credentials.t option;
      (** Access key, secret, optional session token. [None] selects anonymous
          mode: requests are sent unsigned, with no [Authorization] header, for
          reading public buckets. *)
  path_style : bool;
      (** When [true] (the default via {!make_config}), objects are addressed as
          [endpoint/bucket/key]. RGW and MinIO require this unless configured
          for virtual-host addressing. *)
  tls_verification : tls_verification;
      (** Certificate verification policy for [https://] endpoints. *)
  max_connections : int;
      (** Maximum number of pooled connections to the endpoint kept open at
          once. This also bounds how many requests (e.g. multipart parts) run
          concurrently. *)
  payload_hash : string -> string;
      (** Computes the [x-amz-content-sha256] value for a (non-empty) request
          body. Defaults to {!Auth.hex_sha256} — the digest the server verifies,
          so it catches in-flight corruption. It is called once per non-empty
          body, possibly concurrently from several fibers (one per in-flight
          multipart part), so it must be fiber-safe.

          Override it to move the (CPU-bound) hashing onto your own executor
          pool — e.g.
          [fun s -> Eio.Executor_pool.submit_exn pool ~weight:1.0 (fun () ->
          Auth.hex_sha256 s)] — or return the literal ["UNSIGNED-PAYLOAD"] to
          skip payload signing entirely (no body-integrity check; only wise over
          TLS or a trusted link). *)
}

(** [make_config ?region ?path_style ?tls_verification ?max_connections
    ?payload_hash ?credentials ~endpoint ()] builds a {!config} with sensible
    defaults ([region = "us-east-1"], [path_style = true],
    [tls_verification = System_trust], [max_connections = 8],
    [payload_hash = Auth.hex_sha256]).
    See {!module:Credentials} for resolving [credentials] from the environment
    or a shared credentials file. Omitting [credentials] selects anonymous
    mode (unsigned requests) for reading public buckets. See the [payload_hash]
    field for offloading body hashing or disabling payload signing. *)
val make_config :
  ?region:string ->
  ?path_style:bool ->
  ?tls_verification:tls_verification ->
  ?max_connections:int ->
  ?payload_hash:(string -> string) ->
  ?credentials:Credentials.t ->
  endpoint:string ->
  unit ->
  config

(** A client handle. Cheap to create and safe to share between fibers; each
    request opens its own connection. *)
type t

(** [create ~sw ~net ~clock config] is a client using [net] for connections and
    [clock] for request timestamps. Pooled keep-alive connections are attached
    to [sw], so they are closed when it finishes; the client must not be used
    beyond [sw]'s lifetime.

    For [https://] endpoints this initialises the global crypto RNG (via
    [Mirage_crypto_rng_unix.use_default], once per process, backed by the OS
    [getrandom]) so TLS works without additional caller setup. *)
val create :
  sw:Eio.Switch.t -> net:_ Eio.Net.t -> clock:_ Eio.Time.clock -> config -> t

(** A structured error. For an HTTP-level failure it is decoded from the
    server's XML error document where available. Failures where no HTTP response
    was received — a transport error (timeout, connection/TLS), or a client-side
    precondition (e.g. an upload exceeding the part limit) — are reported the
    same way, with [http_status = 0].

    Operations return all failures — including transport ones — as [Error]; the
    client does not raise for network errors. (Caller-initiated cancellation via
    a failing {!Eio.Switch.t} still propagates as an exception, as usual.) *)
type error = {
  http_status : int;
      (** HTTP status code, or [0] when no HTTP response was received. *)
  code : string;
      (** S3 error code, e.g. ["NoSuchKey"]; ["Timeout"]/["Transport"] for a
          transport failure; ["TooManyParts"] for the part-limit precondition;
          or [""] if unknown. *)
  message : string;  (** Human-readable message. *)
}

val pp_error : Format.formatter -> error -> unit

(** Object metadata, as returned by {!head_object}. *)
type metadata = {
  content_length : int;
  content_type : string option;
  etag : string option;  (** Entity tag, including its surrounding quotes. *)
  last_modified : string option;
  user_metadata : (string * string) list;
      (** User metadata, with the [x-amz-meta-] prefix stripped from the keys. *)
}

(** {1 Bucket operations} *)

val create_bucket : t -> bucket:string -> (unit, error) result
val delete_bucket : t -> bucket:string -> (unit, error) result

(** [bucket_exists t ~bucket] is [Ok true]/[Ok false]; other errors (e.g. auth
    failures) are returned as [Error]. *)
val bucket_exists : t -> bucket:string -> (bool, error) result

(** {1 Object operations} *)

(** [put_string t ~bucket ~key ?content_type ?metadata data] uploads [data] as a
    single object and returns its ETag. [metadata] keys are sent as
    [x-amz-meta-<key>] headers. *)
val put_string :
  t ->
  bucket:string ->
  key:string ->
  ?content_type:string ->
  ?metadata:(string * string) list ->
  string ->
  (string, error) result

(** [put_file t ~bucket ~key ~path ()] uploads the file at [path]. Files at or
    below [multipart_threshold] are sent with a single PUT; larger files use a
    multipart upload of [part_size]-byte parts, with up to [max_concurrency]
    parts in flight at once. Returns the object's ETag.

    @param part_size bytes per part (default 8 MiB; S3 requires >= 5 MiB).
    @param multipart_threshold switch-over size (default 16 MiB).
    @param max_concurrency maximum parts uploaded concurrently (default 4). *)
val put_file :
  t ->
  bucket:string ->
  key:string ->
  ?content_type:string ->
  ?metadata:(string * string) list ->
  ?part_size:int ->
  ?multipart_threshold:int ->
  ?max_concurrency:int ->
  path:_ Eio.Path.t ->
  unit ->
  (string, error) result

(** [get_string t ~bucket ~key ()] downloads an object into a string.
    @param max_size cap on the object size accepted, in bytes (default 128 MiB),
      to bound memory use. *)
val get_string :
  t ->
  bucket:string ->
  key:string ->
  ?max_size:int ->
  unit ->
  (string, error) result

(** [get_to_file t ~bucket ~key ~path] streams an object to the file at [path],
    truncating any existing file. Memory use is bounded regardless of size. *)
val get_to_file :
  t -> bucket:string -> key:string -> path:_ Eio.Path.t -> (unit, error) result

(** [get_range t ~bucket ~key ~first ~last ()] downloads the inclusive byte
    range [\[first, last\]] of an object via an HTTP [Range] request, returning
    just those bytes. The server answers [206 Partial Content]; the result
    string is [last - first + 1] bytes. Returns [Error] if [last < first].
    Useful for reading a small slice of a large object without fetching it
    whole. *)
val get_range :
  t ->
  bucket:string ->
  key:string ->
  first:int ->
  last:int ->
  unit ->
  (string, error) result

(** [head_object t ~bucket ~key] fetches object metadata without the body. *)
val head_object : t -> bucket:string -> key:string -> (metadata, error) result

val delete_object : t -> bucket:string -> key:string -> (unit, error) result

(** [copy_object t ~src_bucket ~src_key ~dst_bucket ~dst_key ()] performs a
    server-side copy (via [x-amz-copy-source]); the object bytes do not pass
    through the client. Source and destination must be on the same endpoint.
    Returns the destination ETag.

    The source is first HEADed to learn its size. Objects at or below
    [multipart_threshold] (default 5 GiB, the single-copy limit) are copied in
    one request; larger ones use a multipart copy ([UploadPartCopy]) of
    [part_size]-byte ranges (default 512 MiB), up to [max_concurrency] at once
    (default 4).

    By default the source object's metadata and content type are preserved;
    passing [content_type] or [metadata] replaces them instead. *)
val copy_object :
  t ->
  src_bucket:string ->
  src_key:string ->
  dst_bucket:string ->
  dst_key:string ->
  ?content_type:string ->
  ?metadata:(string * string) list ->
  ?part_size:int ->
  ?multipart_threshold:int ->
  ?max_concurrency:int ->
  unit ->
  (string, error) result

(** An object as reported by a listing. *)
type entry = {
  key : string;
  size : int;  (** Size in bytes. *)
  etag : string option;
  last_modified : string option;  (** ISO-8601 timestamp string. *)
}

(** A single page of a listing. *)
type page = {
  objects : entry list;
  next_continuation_token : string option;
      (** Token to pass as [continuation_token] for the next page, or [None]
          when this is the last page. *)
}

(** [list_page t ~bucket ?prefix ?continuation_token ?max_keys ()] fetches one
    page of a [ListObjectsV2] listing (the low-level primitive). *)
val list_page :
  t ->
  bucket:string ->
  ?prefix:string ->
  ?continuation_token:string ->
  ?max_keys:int ->
  unit ->
  (page, error) result

(** [fold_pages t ~bucket ?prefix ?max_keys_per_page ~init ~f ()] folds [f] over
    every {e page} under [prefix], following continuation tokens across all
    pages. Pages are fetched sequentially (each depends on the previous token);
    folding per page lets callers track page boundaries (e.g. for progress).
    Stops and returns [Error] on the first failed page. *)
val fold_pages :
  t ->
  bucket:string ->
  ?prefix:string ->
  ?max_keys_per_page:int ->
  init:'a ->
  f:('a -> page -> 'a) ->
  unit ->
  ('a, error) result

(** [iter_objects t ~bucket ?prefix ?max_keys_per_page ~f ()] calls [f] on every
    object under [prefix] across all pages, returning the total count. *)
val iter_objects :
  t ->
  bucket:string ->
  ?prefix:string ->
  ?max_keys_per_page:int ->
  f:(entry -> unit) ->
  unit ->
  (int, error) result

(** [list_objects t ~bucket ?prefix ()] collects every key under [prefix] into a
    list (following all pages). Convenient for small listings; for large ones
    prefer {!iter_objects} or {!fold_pages} to bound memory. *)
val list_objects :
  t ->
  bucket:string ->
  ?prefix:string ->
  ?max_keys_per_page:int ->
  unit ->
  (string list, error) result
