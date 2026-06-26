type credentials = {
  access_key : string;
  secret_key : string;
}

module H = Digestif.SHA256

let hex_sha256 s = H.(to_hex (digest_string s))
let empty_payload_hash = hex_sha256 ""

(* Raw (binary) HMAC-SHA256, used when chaining to derive the signing key. *)
let hmac_raw ~key data = H.(to_raw_string (hmac_string ~key data))

(* Hex HMAC-SHA256, used for the final signature. *)
let hmac_hex ~key data = H.(to_hex (hmac_string ~key data))

(* SigV4 percent-encoding. Deliberately hand-rolled rather than using [Uri]:
   the signature requires this exact unreserved set ([A-Za-z0-9-_.~]), uppercase
   [%XX] hex, and the [encode_slash] distinction (slashes are preserved in the
   canonical path but encoded in query parameters). [Uri]'s component encoders
   follow different rules, so substituting them would silently break the
   signature (SignatureDoesNotMatch). Same reason [canonical_query] builds the
   query string by hand instead of via [Uri.encoded_of_query]. *)
let uri_encode ~encode_slash s =
  let buf = Buffer.create (String.length s) in
  String.iter
    (fun c ->
      match c with
      | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' | '.' | '~' ->
          Buffer.add_char buf c
      | '/' when not encode_slash -> Buffer.add_char buf c
      | c -> Buffer.add_string buf (Printf.sprintf "%%%02X" (Char.code c)))
    s;
  Buffer.contents buf

let amz_date_of_posix t =
  let tm = Unix.gmtime t in
  Printf.sprintf "%04d%02d%02dT%02d%02d%02dZ" (tm.Unix.tm_year + 1900)
    (tm.Unix.tm_mon + 1) tm.Unix.tm_mday tm.Unix.tm_hour tm.Unix.tm_min
    tm.Unix.tm_sec

(* The date stamp [YYYYMMDD] is the first eight characters of the timestamp. *)
let date_stamp_of_amz_date amz_date = String.sub amz_date 0 8

let canonical_query query =
  query
  |> List.map (fun (k, v) ->
         (uri_encode ~encode_slash:true k, uri_encode ~encode_slash:true v))
  |> List.sort compare
  |> List.map (fun (k, v) -> k ^ "=" ^ v)
  |> String.concat "&"

(* Headers normalised for signing: lower-cased names, trimmed values, sorted
   by name. Returns the pairs together with the [SignedHeaders] string. *)
let normalise_headers headers =
  let normalised =
    headers
    |> List.map (fun (k, v) -> (String.lowercase_ascii k, String.trim v))
    |> List.sort (fun (a, _) (b, _) -> String.compare a b)
  in
  let canonical_headers =
    normalised
    |> List.map (fun (k, v) -> k ^ ":" ^ v ^ "\n")
    |> String.concat ""
  in
  let signed_headers = normalised |> List.map fst |> String.concat ";" in
  (canonical_headers, signed_headers)

let canonical_request ~meth ~path ~query ~canonical_headers ~signed_headers
    ~payload_hash =
  let canonical_uri = uri_encode ~encode_slash:false path in
  String.concat "\n"
    [
      meth;
      canonical_uri;
      canonical_query query;
      canonical_headers;
      signed_headers;
      payload_hash;
    ]

let signing_key ~secret ~date_stamp ~region ~service =
  let k_date = hmac_raw ~key:("AWS4" ^ secret) date_stamp in
  let k_region = hmac_raw ~key:k_date region in
  let k_service = hmac_raw ~key:k_region service in
  hmac_raw ~key:k_service "aws4_request"

let authorization_header ~credentials ~region ~service ~meth ~path ~query
    ~headers ~payload_hash ~amz_date =
  let date_stamp = date_stamp_of_amz_date amz_date in
  let canonical_headers, signed_headers = normalise_headers headers in
  let creq =
    canonical_request ~meth ~path ~query ~canonical_headers ~signed_headers
      ~payload_hash
  in
  let credential_scope =
    String.concat "/" [ date_stamp; region; service; "aws4_request" ]
  in
  let string_to_sign =
    String.concat "\n"
      [
        "AWS4-HMAC-SHA256";
        amz_date;
        credential_scope;
        hex_sha256 creq;
      ]
  in
  let key =
    signing_key ~secret:credentials.secret_key ~date_stamp ~region ~service
  in
  let signature = hmac_hex ~key string_to_sign in
  Printf.sprintf
    "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
    credentials.access_key credential_scope signed_headers signature
