(** AWS Signature Version 4 request signing.

    This implements the {{:https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html}
    SigV4} algorithm used by Amazon S3 and S3-compatible servers such as Ceph
    RGW and MinIO. The functions here are pure and deterministic, which makes
    them straightforward to unit-test against the published AWS test vectors. *)

type credentials = {
  access_key : string;  (** AWS access key id. *)
  secret_key : string;  (** AWS secret access key. *)
}

(** [hex_sha256 s] is the lowercase hexadecimal SHA-256 digest of [s]. *)
val hex_sha256 : string -> string

(** The SHA-256 digest of the empty string, a SigV4 constant used as the
    payload hash for requests with no body. *)
val empty_payload_hash : string

(** [uri_encode ~encode_slash s] percent-encodes [s] per RFC 3986. The
    unreserved characters [A-Za-z0-9-_.~] are left as-is; everything else is
    encoded as [%XX] with uppercase hex. When [encode_slash] is [false], ['/']
    is also left as-is, as required for S3 canonical object paths. *)
val uri_encode : encode_slash:bool -> string -> string

(** [amz_date_of_posix t] formats the POSIX time [t] (seconds since the epoch,
    UTC) as the ISO-8601 basic timestamp ["YYYYMMDDTHHMMSSZ"] expected in the
    [x-amz-date] header. *)
val amz_date_of_posix : float -> string

(** [authorization_header ~credentials ~region ~service ~meth ~path ~query
    ~headers ~payload_hash ~amz_date] is the value for the HTTP [Authorization]
    header that authenticates the described request.

    - [meth] is the upper-case HTTP method, e.g. ["GET"].
    - [path] is the {e unencoded} request path, e.g. ["/bucket/my key"]; it is
      percent-encoded internally (preserving ['/']).
    - [query] is the list of unencoded query parameters.
    - [headers] is the list of headers to sign as [(name, value)] pairs. It must
      include at least [host], [x-amz-content-sha256] and [x-amz-date]. Names
      are treated case-insensitively.
    - [payload_hash] is the hex SHA-256 of the request body (see
      {!hex_sha256} / {!empty_payload_hash}).
    - [amz_date] is the timestamp from {!amz_date_of_posix}. *)
val authorization_header :
  credentials:credentials ->
  region:string ->
  service:string ->
  meth:string ->
  path:string ->
  query:(string * string) list ->
  headers:(string * string) list ->
  payload_hash:string ->
  amz_date:string ->
  string
