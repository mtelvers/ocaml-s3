type tls_verification =
  | System_trust  (** Verify the server certificate against the OS trust store. *)
  | No_verification  (** Accept any certificate (insecure; testing only). *)
  | Ca_file of string  (** Verify against trust anchors in this PEM file. *)

type config = {
  endpoint : string;
  region : string;
  credentials : Credentials.t option;
      (* [None] makes anonymous, unsigned requests (for public buckets). *)
  path_style : bool;
  tls_verification : tls_verification;
  max_connections : int;
}

let make_config ?(region = "us-east-1") ?(path_style = true)
    ?(tls_verification = System_trust) ?(max_connections = 8) ?credentials
    ~endpoint () =
  { endpoint; region; credentials; path_style; tls_verification; max_connections }

(* A connection usable by cohttp-eio: a two-way flow that can be closed. *)
type conn = [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Resource.t

(* A pool of keep-alive connections to one endpoint. cohttp-eio has no built-in
   connection cache (its client is just [sw -> uri -> connection]) and does no
   liveness checking, so reuse, staleness and timeouts are all ours to manage.
   [make_generic] lets us supply the socket for a request; we hand out pooled
   sockets and recycle them once the response body has been consumed. The
   semaphore bounds the number of live connections; [idle] holds ready-to-reuse
   ones, each stamped with the time it was released.

   Staleness: S3 endpoints (and the load balancers in front of them) routinely
   close idle keep-alive connections. A pooled connection the server has closed
   sits in [CLOSE_WAIT]; writing the next request to it blocks on TCP
   back-pressure forever (no error, no timeout) — a hang. So [acquire] discards
   any idle connection that has sat unused longer than [idle_ttl] and dials a
   fresh one instead. The per-request timeout in [call] is the backstop for the
   race where a connection dies inside that window.

   The target [addr]/[domain] are mutable so the pool can be re-pointed at a
   different host when the server issues a region redirect; [dial] opens a fresh
   connection (TCP, plus a TLS handshake for https) to the current target. *)
module Conn_pool = struct
  type t = {
    dial : string -> [ `host ] Domain_name.t option -> conn;
        (* [dial host domain] resolves [host] and opens a connection to it. *)
    now : unit -> float;
    idle_ttl : float;
    mutable host : string;
    mutable domain : [ `host ] Domain_name.t option;
    mutable idle : (conn * float) list;  (* connection + time it was released *)
    mutex : Eio.Mutex.t;
    sem : Eio.Semaphore.t;
  }

  let create ~host ~domain ~dial ~max ~now ~idle_ttl =
    {
      dial;
      now;
      idle_ttl;
      host;
      domain;
      idle = [];
      mutex = Eio.Mutex.create ();
      sem = Eio.Semaphore.make max;
    }

  (* Pop the most-recently-released idle connection that is still within the
     idle TTL, closing any that have been idle too long. Idle connections hold
     no semaphore permit, so a discarded one is simply closed. *)
  let rec take_fresh_idle t =
    match
      Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
          match t.idle with
          | entry :: rest ->
              t.idle <- rest;
              Some entry
          | [] -> None)
    with
    | None -> None
    | Some (c, released) ->
        if t.now () -. released > t.idle_ttl then begin
          (try Eio.Resource.close c with _ -> ());
          take_fresh_idle t
        end
        else Some c

  (* Acquire a connection, reusing a fresh-enough idle one if available.
     Returns the connection and whether it was freshly opened (vs. reused). *)
  let acquire t : conn * bool =
    Eio.Semaphore.acquire t.sem;
    match take_fresh_idle t with
    | Some c -> (c, false)
    | None -> (
        (* No fresh idle connection; open a new one (still holding a permit). *)
        try (t.dial t.host t.domain, true)
        with e ->
          Eio.Semaphore.release t.sem;
          raise e)

  let release t (c : conn) =
    Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
        t.idle <- (c, t.now ()) :: t.idle);
    Eio.Semaphore.release t.sem

  let discard t (c : conn) =
    (try Eio.Resource.close c with _ -> ());
    Eio.Semaphore.release t.sem

  (* Re-point the pool at a new host, closing any idle connections to the old
     one. Connections currently checked out are discarded on release because
     they reach a server that redirects them. *)
  let retarget t ~host ~domain =
    Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
        List.iter (fun (c, _) -> try Eio.Resource.close c with _ -> ()) t.idle;
        t.idle <- [];
        t.host <- host;
        t.domain <- domain)
end

(* Existential wrapper so the polymorphic Eio clock can live in the record;
   unpacked where [Eio.Time.with_timeout_exn] needs it. *)
type any_clock = Clock : _ Eio.Time.clock -> any_clock

type t = {
  config : config;
  pool : Conn_pool.t;
  now : unit -> float;
  clock : any_clock;  (* for per-request timeouts *)
  scheme : string;
  port_suffix : string;  (* ":port" or "" *)
  retarget_mutex : Eio.Mutex.t;  (* serialises region redirects *)
  mutable host : string;  (* current endpoint host (may change on redirect) *)
  mutable region : string;  (* current signing region (may change on redirect) *)
}

(* The base URL and Host header are derived from the current host. *)
let base t = Printf.sprintf "%s://%s%s" t.scheme t.host t.port_suffix
let host_header t = t.host ^ t.port_suffix

type error = {
  http_status : int;
      (* The response's HTTP status, or [0] for a transport-level failure
         (timeout, connection/TLS error) where no HTTP response was received; in
         that case [code] is a symbolic tag and [message] the detail. *)
  code : string;
  message : string;
}

let pp_error fmt e =
  let code_msg fmt e =
    Format.fprintf fmt "%s%s"
      (if e.code = "" then "" else ": " ^ e.code)
      (if e.message = "" then "" else " - " ^ e.message)
  in
  if e.http_status = 0 then Format.fprintf fmt "S3 error%a" code_msg e
  else Format.fprintf fmt "S3 error (HTTP %d)%a" e.http_status code_msg e

(* An [error] for a transport-level failure: no HTTP response was received, so
   [http_status] is [0], [code] a symbolic tag, and [message] the detail. *)
let transport_error = function
  | Eio.Time.Timeout ->
      { http_status = 0; code = "Timeout";
        message = "request exceeded the response timeout" }
  | e -> { http_status = 0; code = "Transport"; message = Printexc.to_string e }

type metadata = {
  content_length : int;
  content_type : string option;
  etag : string option;
  last_modified : string option;
  user_metadata : (string * string) list;
}

let src = Logs.Src.create "s3" ~doc:"S3 client"

module Log = (val Logs.src_log src)

(* The TLS stack (ocaml-tls) draws randomness from Mirage_crypto_rng's global
   generator. [use_default] registers an OS-getrandom-backed generator; we do it
   lazily, once per process, so HTTPS works out of the box without the caller
   having to set up the RNG. It is harmless for plain-HTTP use. *)
let ensure_rng = lazy (Mirage_crypto_rng_unix.use_default ())

let read_file path = In_channel.with_open_bin path In_channel.input_all

let build_authenticator ~now = function
  | System_trust -> (
      match Ca_certs.authenticator () with
      | Ok a -> a
      | Error (`Msg m) ->
          failwith ("s3: could not load system trust store: " ^ m))
  | No_verification ->
      (* Accept any chain. [Validation.r]'s [Ok] carries an optional chain. *)
      fun ?ip:_ ~host:_ _certs -> Ok None
  | Ca_file path -> (
      match X509.Certificate.decode_pem_multiple (read_file path) with
      | Ok anchors ->
          X509.Authenticator.chain_of_trust
            ~time:(fun () -> Ptime.of_float_s (now ()))
            anchors
      | Error (`Msg m) ->
          failwith (Printf.sprintf "s3: could not load CA file %s: %s" path m)
      | exception Sys_error m ->
          failwith (Printf.sprintf "s3: could not read CA file %s: %s" path m))

(* Build a TLS client config (authenticator + handshake settings) used when
   opening https connections. *)
let make_tls_config ~now ~tls_verification =
  Lazy.force ensure_rng;
  let authenticator = build_authenticator ~now tls_verification in
  match Tls.Config.client ~authenticator () with
  | Ok c -> c
  | Error (`Msg m) -> failwith ("s3: invalid TLS configuration: " ^ m)

let domain_of_host host =
  try Some (Domain_name.host_exn (Domain_name.of_string_exn host)) with _ -> None

(* Pooled connections idle longer than this are assumed possibly closed by the
   server / a load balancer and are discarded rather than reused (S3 LBs
   routinely drop idle keep-alives). Short enough to retire sporadic
   connections, long enough to reuse within a multipart burst. *)
let idle_connection_ttl = 10.0

(* Timeout bounding a single request attempt up to the point the response
   headers arrive — connection, request send, and the wait for the status line
   and headers. It deliberately does {e not} cover streaming the response body,
   so a large or slow download is never killed mid-transfer. Its purpose is the
   original backstop: a write wedged on a half-closed pooled connection (blocked
   on TCP back-pressure to a peer that has gone away) raises nothing and never
   returns — cohttp-eio has no timeout — so cap the request phase here. On expiry
   the attempt is treated like any other failure: the connection is discarded
   and, if it was reused, the request is retried on a fresh connection. *)
let response_timeout = 120.0

(* Per-address TCP connect timeout. Bounds each connect attempt so a black-holed
   address fails over to the next quickly instead of hanging (the OS connect
   timeout can be minutes). Generous — a healthy connect is well under a second. *)
let connect_timeout = 10.0

let create ~sw ~net ~clock config =
  let uri = Uri.of_string config.endpoint in
  let scheme = Option.value ~default:"http" (Uri.scheme uri) in
  let host = Option.value ~default:"localhost" (Uri.host uri) in
  let port = Uri.port uri in
  let port_suffix =
    match port with Some p -> ":" ^ string_of_int p | None -> ""
  in
  let now () = Eio.Time.now clock in
  let service = match port with Some p -> string_of_int p | None -> scheme in
  let tls_config =
    if scheme = "https" then
      Some (make_tls_config ~now ~tls_verification:config.tls_verification)
    else None
  in
  (* Round-robin starting offset so successive dials spread across all the
     addresses a load-balanced host publishes (e.g. an RGW behind many IPs)
     rather than pinning to whichever the resolver lists first. *)
  let dial_rotation = ref 0 in
  (* Open a new connection to a target host: resolve it, then connect (TCP),
     trying each resolved address in turn — starting at the rotating offset and
     wrapping — so a dead address fails over to the next and load spreads across
     them. For https the TLS handshake runs once per connection, amortised
     across reuse. Resolution and connection happen here, at dial time, so DNS
     and connect failures surface through [call]'s error handling as an [Error]
     rather than raising from [create]. *)
  let dial host domain : conn =
    let addrs = Array.of_list (Eio.Net.getaddrinfo_stream ~service net host) in
    let n = Array.length addrs in
    if n = 0 then Fmt.failwith "s3: could not resolve host %s" host;
    let start = !dial_rotation mod n in
    incr dial_rotation;
    let connect_tcp addr =
      Eio.Time.with_timeout_exn clock connect_timeout (fun () ->
          Eio.Net.connect ~sw net addr)
    in
    let rec connect i =
      let addr = addrs.((start + i) mod n) in
      if i = n - 1 then connect_tcp addr (* last candidate: let its error stand *)
      else
        try connect_tcp addr with
        | Eio.Cancel.Cancelled _ as e -> raise e
        | _ -> connect (i + 1)
    in
    let tcp = connect 0 in
    match tls_config with
    | None -> (tcp :> conn)
    | Some cfg -> (Tls_eio.client_of_flow cfg ?host:domain tcp :> conn)
  in
  let pool =
    Conn_pool.create ~host ~domain:(domain_of_host host) ~dial
      ~max:config.max_connections ~now ~idle_ttl:idle_connection_ttl
  in
  {
    config;
    pool;
    now;
    clock = Clock clock;
    scheme;
    port_suffix;
    retarget_mutex = Eio.Mutex.create ();
    host;
    region = config.region;
  }

(* The canonical query string per SigV4: parameters percent-encoded and sorted.
   We reuse this exact string in the request target so that what we sign is what
   we send. *)
let query_string = function
  | [] -> ""
  | query ->
      let encoded =
        query
        |> List.map (fun (k, v) ->
               ( Auth.uri_encode ~encode_slash:true k,
                 Auth.uri_encode ~encode_slash:true v ))
        |> List.sort compare
        |> List.map (fun (k, v) -> k ^ "=" ^ v)
        |> String.concat "&"
      in
      "?" ^ encoded

let raw_path ~bucket ~key =
  if key = "" then "/" ^ bucket else "/" ^ bucket ^ "/" ^ key

let auth_credentials (creds : Credentials.t) =
  {
    Auth.access_key = creds.Credentials.access_key;
    secret_key = creds.Credentials.secret_key;
  }

let connection_should_close resp =
  match Http.Header.get (Http.Response.headers resp) "connection" with
  | Some v -> String.lowercase_ascii (String.trim v) = "close"
  | None -> false

let status_code resp = Http.Status.to_int (Http.Response.status resp)
let is_success resp = status_code resp >= 200 && status_code resp < 300

(* {2 Region-redirect following} *)

(* Index of the first occurrence of [sub] in [s], if any. *)
let find_sub s sub =
  let n = String.length s and m = String.length sub in
  if m = 0 then Some 0
  else
    let rec loop i =
      if i + m > n then None
      else if String.sub s i m = sub then Some i
      else loop (i + 1)
    in
    loop 0

let replace_first s ~sub ~by =
  match find_sub s sub with
  | None -> s
  | Some i ->
      String.sub s 0 i ^ by
      ^ String.sub s (i + String.length sub)
          (String.length s - i - String.length sub)

(* Work out the host for a bucket that lives in [new_region], given the current
   [old_host]/[old_region]. Handles AWS regional endpoints (replace the region
   token, or build [s3.<region>.amazonaws.com] for the regionless endpoint).
   Returns [None] for hosts we don't know how to rewrite (e.g. a custom RGW),
   in which case we do not follow. *)
let derive_host ~old_host ~old_region ~new_region =
  if old_region <> "" && find_sub old_host old_region <> None then
    Some (replace_first old_host ~sub:old_region ~by:new_region)
  else if String.ends_with ~suffix:"amazonaws.com" old_host then
    Some ("s3." ^ new_region ^ ".amazonaws.com")
  else None

(* If [resp] is an unsuccessful response naming a different bucket region (via
   the [x-amz-bucket-region] header S3 returns on 301/307/400 redirects), that
   region; otherwise [None]. *)
let redirect_region t resp =
  if is_success resp then None
  else
    match Http.Header.get (Http.Response.headers resp) "x-amz-bucket-region" with
    | Some r when r <> "" && not (String.equal r t.region) -> Some r
    | _ -> None

(* Re-point the client (and its pool) at [new_region]. Idempotent and
   serialised, so concurrent redirects converge. Returns whether following is
   possible: [`Cannot] means we could not rewrite the host and should stop. *)
let retarget t ~new_region =
  Eio.Mutex.use_rw ~protect:true t.retarget_mutex (fun () ->
      if String.equal new_region t.region then `Already
      else
        match
          derive_host ~old_host:t.host ~old_region:t.region ~new_region
        with
        | None -> `Cannot
        | Some new_host ->
            Conn_pool.retarget t.pool ~host:new_host
              ~domain:(domain_of_host new_host);
            t.host <- new_host;
            t.region <- new_region;
            Log.debug (fun m ->
                m "following region redirect to %s (%s)" new_region new_host);
            `Retargeted)

(* Run a single signed request. [f] is called with the response and its body
   flow, which it must consume before returning (so the connection is left at a
   clean boundary and can be recycled).

   The connection comes from the pool; on success it is returned for reuse
   (unless the server asked to close), and on failure it is discarded. A request
   that fails on a {e reused} connection is retried once on a fresh one, to
   absorb connections the server closed while they sat idle. If the server
   redirects to another region, the client is re-pointed there and the request
   replayed (up to a small bound). *)
let call t ~meth ~bucket ~key ?(query = []) ?(extra_headers = []) ?(body = "") f
    =
  let path = raw_path ~bucket ~key in
  let payload_hash =
    if body = "" then Auth.empty_payload_hash else Auth.hex_sha256 body
  in
  (* [follow] is the number of region redirects we are still willing to chase. *)
  let rec go ~follow =
    let headers =
      match t.config.credentials with
      | None ->
          (* Anonymous (unsigned) request: no SigV4 signature, no Authorization
             header, no x-amz-date. For public buckets / objects. *)
          Http.Header.of_list (("host", host_header t) :: extra_headers)
      | Some creds ->
          let amz_date = Auth.amz_date_of_posix (t.now ()) in
          let signed_headers =
            [
              ("host", host_header t);
              ("x-amz-content-sha256", payload_hash);
              ("x-amz-date", amz_date);
            ]
            @ (match creds.Credentials.session_token with
              | Some tok -> [ ("x-amz-security-token", tok) ]
              | None -> [])
            @ extra_headers
          in
          let authorization =
            Auth.authorization_header ~credentials:(auth_credentials creds)
              ~region:t.region ~service:"s3"
              ~meth:(Http.Method.to_string meth)
              ~path ~query ~headers:signed_headers ~payload_hash ~amz_date
          in
          Http.Header.of_list
            (("Authorization", authorization) :: signed_headers)
    in
    let target =
      Auth.uri_encode ~encode_slash:false path ^ query_string query
    in
    let uri = Uri.of_string (base t ^ target) in
    Log.debug (fun m -> m "%a %s" Http.Method.pp meth target);
    let (Clock clk) = t.clock in
    let attempt () =
      (* Acquiring dials a fresh connection when the pool has no live idle one;
         a connect/TLS failure here is a transport error. On that path [acquire]
         has already released its permit and there is no connection to discard,
         so surface it directly (no retry — an immediate redial would just fail
         again). *)
      match Conn_pool.acquire t.pool with
      | exception (Eio.Cancel.Cancelled _ as e) -> raise e
      | exception e -> `Failed (transport_error e)
      | conn, fresh -> (
      (* cohttp-eio drives the HTTP over the connection we hand it; it never
         closes the socket, so we own its lifecycle. *)
      let client = Cohttp_eio.Client.make_generic (fun ~sw:_ _uri -> conn) in
      match
        Eio.Switch.run (fun sw ->
            (* Time only the request phase — connect, send, and receiving the
               response headers (see [response_timeout]). The body, streamed by
               [f] below, runs untimed so large downloads are not killed. *)
            let resp, rbody =
              Eio.Time.with_timeout_exn clk response_timeout (fun () ->
                  Cohttp_eio.Client.call client ~sw ~headers
                    ~body:(Cohttp_eio.Body.of_string body) meth uri)
            in
            match (if follow > 0 then redirect_region t resp else None) with
            | Some new_region ->
                (* Drain the (small) redirect body so the connection stays
                   reusable, then signal a redirect rather than calling [f]. *)
                let _ : string =
                  Eio.Buf_read.parse_exn Eio.Buf_read.take_all ~max_size:65536
                    rbody
                in
                `Redirect (resp, new_region)
            | None -> `Done (resp, f resp rbody))
      with
      | `Done (resp, result) ->
          if connection_should_close resp then Conn_pool.discard t.pool conn
          else Conn_pool.release t.pool conn;
          `Ok result
      | `Redirect (resp, new_region) ->
          if connection_should_close resp then Conn_pool.discard t.pool conn
          else Conn_pool.release t.pool conn;
          `Follow new_region
      | exception (Eio.Cancel.Cancelled _ as e) ->
          (* External cancellation (caller's switch failing) must propagate,
             not be turned into a retry or an [Error]. *)
          Conn_pool.discard t.pool conn;
          raise e
      | exception e ->
          (* Transport failure: timeout, connection/TLS error, or a body stream
             that died mid-read. Retry once on a fresh connection to absorb a
             server-closed idle socket; otherwise surface it as an [Error]
             rather than letting it escape the result-typed API. *)
          Conn_pool.discard t.pool conn;
          if fresh then `Failed (transport_error e) else `Retry_conn)
    in
    match attempt () with
    | `Ok result -> result
    | `Failed error -> Error error
    | `Retry_conn -> go ~follow (* stale reused connection; retry as-is *)
    | `Follow new_region -> (
        match retarget t ~new_region with
        | `Cannot -> go ~follow:0 (* can't rewrite host; surface the error *)
        | `Already | `Retargeted -> go ~follow:(follow - 1))
  in
  go ~follow:3

(* Drain a response body into a string, with a size cap to bound memory. *)
let read_body ?(max_size = 16 * 1024 * 1024) rbody =
  Eio.Buf_read.parse_exn Eio.Buf_read.take_all ~max_size rbody

let error_of_response resp body =
  let code, message =
    match Xml_util.parse_string body with
    | Some tree ->
        ( Option.value ~default:"" (Xml_util.find_text "Code" tree),
          Option.value ~default:"" (Xml_util.find_text "Message" tree) )
    | None -> ("", body)
  in
  { http_status = status_code resp; code; message }

(* For responses without a body (e.g. HEAD), build an error from status alone. *)
let error_of_status resp = { http_status = status_code resp; code = ""; message = "" }

let etag_of_response resp =
  Http.Header.get (Http.Response.headers resp) "etag"

let meta_headers metadata =
  List.map (fun (k, v) -> ("x-amz-meta-" ^ k, v)) metadata

(* {1 Bucket operations} *)

let create_bucket t ~bucket =
  call t ~meth:`PUT ~bucket ~key:"" (fun resp rbody ->
      if is_success resp then Ok ()
      else Error (error_of_response resp (read_body rbody)))

let delete_bucket t ~bucket =
  call t ~meth:`DELETE ~bucket ~key:"" (fun resp rbody ->
      if is_success resp then Ok ()
      else Error (error_of_response resp (read_body rbody)))

let bucket_exists t ~bucket =
  call t ~meth:`HEAD ~bucket ~key:"" (fun resp _rbody ->
      if is_success resp then Ok true
      else if status_code resp = 404 then Ok false
      else Error (error_of_status resp))

(* {1 Object operations} *)

let put_string t ~bucket ~key ?content_type ?(metadata = []) body =
  let extra_headers =
    (match content_type with Some ct -> [ ("content-type", ct) ] | None -> [])
    @ meta_headers metadata
  in
  call t ~meth:`PUT ~bucket ~key ~extra_headers ~body (fun resp rbody ->
      if is_success resp then
        Ok (Option.value ~default:"" (etag_of_response resp))
      else Error (error_of_response resp (read_body rbody)))

let get_string t ~bucket ~key ?(max_size = 128 * 1024 * 1024) () =
  call t ~meth:`GET ~bucket ~key (fun resp rbody ->
      if is_success resp then Ok (read_body ~max_size rbody)
      else Error (error_of_response resp (read_body rbody)))

let get_to_file t ~bucket ~key ~path =
  call t ~meth:`GET ~bucket ~key (fun resp rbody ->
      if is_success resp then begin
        Eio.Path.with_open_out ~create:(`Or_truncate 0o644) path (fun sink ->
            Eio.Flow.copy rbody sink);
        Ok ()
      end
      else Error (error_of_response resp (read_body rbody)))

let metadata_of_response resp =
  let headers = Http.Response.headers resp in
  let get name = Http.Header.get headers name in
  let content_length =
    match get "content-length" with
    | Some s -> ( try int_of_string (String.trim s) with _ -> 0)
    | None -> 0
  in
  let user_metadata =
    Http.Header.to_list headers
    |> List.filter_map (fun (k, v) ->
           let k = String.lowercase_ascii k in
           let prefix = "x-amz-meta-" in
           if String.length k > String.length prefix
              && String.sub k 0 (String.length prefix) = prefix
           then
             Some
               ( String.sub k (String.length prefix)
                   (String.length k - String.length prefix),
                 v )
           else None)
  in
  {
    content_length;
    content_type = get "content-type";
    etag = get "etag";
    last_modified = get "last-modified";
    user_metadata;
  }

let head_object t ~bucket ~key =
  call t ~meth:`HEAD ~bucket ~key (fun resp _rbody ->
      if is_success resp then Ok (metadata_of_response resp)
      else Error (error_of_status resp))

let delete_object t ~bucket ~key =
  call t ~meth:`DELETE ~bucket ~key (fun resp rbody ->
      if is_success resp then Ok ()
      else Error (error_of_response resp (read_body rbody)))

type entry = {
  key : string;
  size : int;
  etag : string option;
  last_modified : string option;
}

type page = {
  objects : entry list;
  next_continuation_token : string option;
}

(* The listing body can be large (1000 keys); allow a generous read cap. *)
let list_max_body = 32 * 1024 * 1024

let entry_of_contents node =
  match Xml_util.find_text "Key" node with
  | None -> None
  | Some key ->
      let size =
        match Xml_util.find_text "Size" node with
        | Some s -> ( try int_of_string (String.trim s) with _ -> 0)
        | None -> 0
      in
      Some
        {
          key;
          size;
          etag = Xml_util.find_text "ETag" node;
          last_modified = Xml_util.find_text "LastModified" node;
        }

let list_page t ~bucket ?prefix ?continuation_token ?(max_keys = 1000) () =
  let query =
    [ ("list-type", "2"); ("max-keys", string_of_int max_keys) ]
    @ (match prefix with Some p -> [ ("prefix", p) ] | None -> [])
    @
    match continuation_token with
    | Some tok -> [ ("continuation-token", tok) ]
    | None -> []
  in
  call t ~meth:`GET ~bucket ~key:"" ~query (fun resp rbody ->
      let body = read_body ~max_size:list_max_body rbody in
      if is_success resp then
        match Xml_util.parse_string body with
        | None -> Ok { objects = []; next_continuation_token = None }
        | Some tree ->
            let objects =
              Xml_util.find_all "Contents" tree
              |> List.filter_map entry_of_contents
            in
            let truncated =
              match Xml_util.find_text "IsTruncated" tree with
              | Some s -> String.equal (String.trim s) "true"
              | None -> false
            in
            let next_continuation_token =
              if truncated then Xml_util.find_text "NextContinuationToken" tree
              else None
            in
            Ok { objects; next_continuation_token }
      else Error (error_of_response resp body))

(* Fold over every page of a listing, following continuation tokens. This is the
   primitive the per-object helpers build on; folding per page (rather than per
   object) lets callers track page boundaries, e.g. for progress reporting. *)
let fold_pages t ~bucket ?prefix ?(max_keys_per_page = 1000) ~init ~f () =
  let rec loop acc continuation_token =
    match
      list_page t ~bucket ?prefix ?continuation_token ~max_keys:max_keys_per_page
        ()
    with
    | Error _ as e -> e
    | Ok page -> (
        let acc = f acc page in
        match page.next_continuation_token with
        | Some _ as tok -> loop acc tok
        | None -> Ok acc)
  in
  loop init None

let iter_objects t ~bucket ?prefix ?max_keys_per_page ~f () =
  fold_pages t ~bucket ?prefix ?max_keys_per_page ~init:0
    ~f:(fun n page ->
      List.iter f page.objects;
      n + List.length page.objects)
    ()

let list_objects t ~bucket ?prefix ?max_keys_per_page () =
  fold_pages t ~bucket ?prefix ?max_keys_per_page ~init:[]
    ~f:(fun acc page ->
      List.rev_append (List.map (fun e -> e.key) page.objects) acc)
    ()
  |> Result.map List.rev

(* {1 Multipart upload} *)

(* Read up to [size] bytes from [flow] into a string; fewer bytes only at EOF.
   Returns "" once the flow is exhausted. *)
let read_chunk flow size =
  let buf = Buffer.create (min size (1024 * 1024)) in
  let cs = Cstruct.create (min size 65536) in
  let rec loop () =
    if Buffer.length buf >= size then ()
    else begin
      let want = min (Cstruct.length cs) (size - Buffer.length buf) in
      match Eio.Flow.single_read flow (Cstruct.sub cs 0 want) with
      | n ->
          Buffer.add_string buf (Cstruct.to_string (Cstruct.sub cs 0 n));
          loop ()
      | exception End_of_file -> ()
    end
  in
  loop ();
  Buffer.contents buf

let initiate_multipart t ~bucket ~key ~extra_headers =
  call t ~meth:`POST ~bucket ~key ~query:[ ("uploads", "") ] ~extra_headers
    (fun resp rbody ->
      let body = read_body rbody in
      if is_success resp then
        match
          Option.bind (Xml_util.parse_string body)
            (Xml_util.find_text "UploadId")
        with
        | Some id -> Ok id
        | None ->
            Error { http_status = status_code resp; code = "MalformedResponse"; message = "missing UploadId" }
      else Error (error_of_response resp body))

let upload_part t ~bucket ~key ~upload_id ~part_number ~body =
  call t ~meth:`PUT ~bucket ~key
    ~query:
      [
        ("partNumber", string_of_int part_number); ("uploadId", upload_id);
      ]
    ~body
    (fun resp rbody ->
      if is_success resp then
        match etag_of_response resp with
        | Some etag -> Ok etag
        | None ->
            Error { http_status = status_code resp; code = "MalformedResponse"; message = "missing ETag on part" }
      else Error (error_of_response resp (read_body rbody)))

let complete_multipart_body parts =
  let buf = Buffer.create 256 in
  Buffer.add_string buf "<CompleteMultipartUpload>";
  List.iter
    (fun (num, etag) ->
      Buffer.add_string buf
        (Printf.sprintf "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>"
           num etag))
    parts;
  Buffer.add_string buf "</CompleteMultipartUpload>";
  Buffer.contents buf

let complete_multipart t ~bucket ~key ~upload_id ~parts =
  let body = complete_multipart_body parts in
  call t ~meth:`POST ~bucket ~key ~query:[ ("uploadId", upload_id) ] ~body
    (fun resp rbody ->
      let rbody = read_body rbody in
      let tree = Xml_util.parse_string rbody in
      (* CompleteMultipartUpload can return HTTP 200 with an error document. *)
      let is_error_doc =
        match tree with
        | Some t -> Xml_util.find_all "Error" t <> []
        | None -> false
      in
      if is_success resp && not is_error_doc then
        Ok
          (Option.bind tree (Xml_util.find_text "ETag")
          |> Option.value ~default:"")
      else Error (error_of_response resp rbody))

let abort_multipart t ~bucket ~key ~upload_id =
  ignore
    (call t ~meth:`DELETE ~bucket ~key ~query:[ ("uploadId", upload_id) ]
       (fun resp rbody ->
         if is_success resp then Ok () else Error (error_of_response resp (read_body rbody))))

(* S3 caps a multipart upload/copy at 10,000 parts. Check up front so an
   over-small part size fails fast with a clear error instead of being rejected
   opaquely at CompleteMultipartUpload after uploading thousands of parts. *)
let max_upload_parts = 10000
let part_count ~size ~part_size = (size + part_size - 1) / part_size

let too_many_parts_error ~size ~part_size =
  {
    http_status = 0;
    code = "TooManyParts";
    message =
      Printf.sprintf
        "%d parts (size %d, part_size %d) exceeds the S3 maximum of %d; use a \
         larger part size"
        (part_count ~size ~part_size) size part_size max_upload_parts;
  }

let multipart_put t ~bucket ~key ~content_type ~metadata ~part_size
    ~max_concurrency ~path =
  let extra_headers =
    (match content_type with Some ct -> [ ("content-type", ct) ] | None -> [])
    @ meta_headers metadata
  in
  match initiate_multipart t ~bucket ~key ~extra_headers with
  | Error _ as e -> e
  | Ok upload_id ->
      let results = ref [] in
      let first_error = ref None in
      let mutex = Eio.Mutex.create () in
      let sem = Eio.Semaphore.make max_concurrency in
      Eio.Path.with_open_in path (fun file ->
          Eio.Switch.run (fun sw ->
              let rec loop part_number =
                if !first_error <> None then ()
                else begin
                  Eio.Semaphore.acquire sem;
                  let chunk = read_chunk file part_size in
                  if chunk = "" then Eio.Semaphore.release sem
                  else begin
                    Eio.Fiber.fork ~sw (fun () ->
                        Fun.protect
                          ~finally:(fun () -> Eio.Semaphore.release sem)
                          (fun () ->
                            match
                              upload_part t ~bucket ~key ~upload_id ~part_number
                                ~body:chunk
                            with
                            | Ok etag ->
                                Eio.Mutex.use_rw ~protect:true mutex (fun () ->
                                    results := (part_number, etag) :: !results)
                            | Error e ->
                                Eio.Mutex.use_rw ~protect:true mutex (fun () ->
                                    if !first_error = None then
                                      first_error := Some e)));
                    loop (part_number + 1)
                  end
                end
              in
              loop 1));
      (match !first_error with
      | Some e ->
          abort_multipart t ~bucket ~key ~upload_id;
          Error e
      | None ->
          let parts =
            List.sort (fun (a, _) (b, _) -> compare a b) !results
          in
          complete_multipart t ~bucket ~key ~upload_id ~parts)

let file_size path =
  Eio.Path.with_open_in path (fun file ->
      Optint.Int63.to_int (Eio.File.size file))

let put_file t ~bucket ~key ?content_type ?(metadata = [])
    ?(part_size = 8 * 1024 * 1024) ?(multipart_threshold = 16 * 1024 * 1024)
    ?(max_concurrency = 4) ~path () =
  let size = file_size path in
  if size <= multipart_threshold then
    let data = Eio.Path.load path in
    put_string t ~bucket ~key ?content_type ~metadata data
  else if part_count ~size ~part_size > max_upload_parts then
    Error (too_many_parts_error ~size ~part_size)
  else
    multipart_put t ~bucket ~key ~content_type ~metadata ~part_size
      ~max_concurrency ~path

(* {1 Server-side copy} *)

let copy_source_header ~src_bucket ~src_key =
  "/" ^ src_bucket ^ "/" ^ Auth.uri_encode ~encode_slash:false src_key

(* Single-shot server-side copy: PUT the destination with [x-amz-copy-source],
   so the bytes are copied by the server. Source <= 5 GiB. *)
let copy_object_single t ~src_bucket ~src_key ~dst_bucket ~dst_key ?content_type
    ?(metadata = []) () =
  (* By default the source's metadata is copied; supplying a content type or
     metadata switches the directive to REPLACE. *)
  let replace = content_type <> None || metadata <> [] in
  let extra_headers =
    [ ("x-amz-copy-source", copy_source_header ~src_bucket ~src_key) ]
    @ (if replace then [ ("x-amz-metadata-directive", "REPLACE") ] else [])
    @ (match content_type with Some ct -> [ ("content-type", ct) ] | None -> [])
    @ meta_headers metadata
  in
  call t ~meth:`PUT ~bucket:dst_bucket ~key:dst_key ~extra_headers
    (fun resp rbody ->
      let body = read_body rbody in
      let tree = Xml_util.parse_string body in
      (* Like CompleteMultipartUpload, CopyObject can return 200 with an error. *)
      let is_error_doc =
        match tree with Some tr -> Xml_util.find_all "Error" tr <> [] | None -> false
      in
      if is_success resp && not is_error_doc then
        Ok (Option.bind tree (Xml_util.find_text "ETag") |> Option.value ~default:"")
      else Error (error_of_response resp body))

(* Copy one part from a byte range of the source ([UploadPartCopy]). Unlike
   [upload_part], the ETag is returned in a <CopyPartResult> body, not a header. *)
let upload_part_copy t ~src_bucket ~src_key ~dst_bucket ~dst_key ~upload_id
    ~part_number ~first ~last =
  let extra_headers =
    [
      ("x-amz-copy-source", copy_source_header ~src_bucket ~src_key);
      ("x-amz-copy-source-range", Printf.sprintf "bytes=%d-%d" first last);
    ]
  in
  call t ~meth:`PUT ~bucket:dst_bucket ~key:dst_key
    ~query:[ ("partNumber", string_of_int part_number); ("uploadId", upload_id) ]
    ~extra_headers
    (fun resp rbody ->
      let body = read_body rbody in
      let tree = Xml_util.parse_string body in
      let is_error_doc =
        match tree with Some tr -> Xml_util.find_all "Error" tr <> [] | None -> false
      in
      if is_success resp && not is_error_doc then
        match Option.bind tree (Xml_util.find_text "ETag") with
        | Some etag -> Ok etag
        | None ->
            Error
              {
                http_status = status_code resp;
                code = "MalformedResponse";
                message = "missing ETag in CopyPartResult";
              }
      else Error (error_of_response resp body))

(* Byte ranges [(part_number, first, last)] covering [size] in [part_size]
   chunks. *)
let copy_ranges ~size ~part_size =
  let rec go n off acc =
    if off >= size then List.rev acc
    else
      let last = min (off + part_size - 1) (size - 1) in
      go (n + 1) (last + 1) ((n, off, last) :: acc)
  in
  go 1 0 []

(* Multipart server-side copy for sources larger than the single-copy limit. *)
let multipart_copy t ~src_bucket ~src_key ~dst_bucket ~dst_key ~content_type
    ~metadata ~part_size ~max_concurrency ~size =
  let extra_headers =
    (match content_type with Some ct -> [ ("content-type", ct) ] | None -> [])
    @ meta_headers metadata
  in
  match initiate_multipart t ~bucket:dst_bucket ~key:dst_key ~extra_headers with
  | Error _ as e -> e
  | Ok upload_id ->
      let results = ref [] in
      let first_error = ref None in
      let mutex = Eio.Mutex.create () in
      let sem = Eio.Semaphore.make max_concurrency in
      Eio.Switch.run (fun sw ->
          List.iter
            (fun (part_number, first, last) ->
              if !first_error <> None then ()
              else begin
                Eio.Semaphore.acquire sem;
                Eio.Fiber.fork ~sw (fun () ->
                    Fun.protect
                      ~finally:(fun () -> Eio.Semaphore.release sem)
                      (fun () ->
                        match
                          upload_part_copy t ~src_bucket ~src_key ~dst_bucket
                            ~dst_key ~upload_id ~part_number ~first ~last
                        with
                        | Ok etag ->
                            Eio.Mutex.use_rw ~protect:true mutex (fun () ->
                                results := (part_number, etag) :: !results)
                        | Error e ->
                            Eio.Mutex.use_rw ~protect:true mutex (fun () ->
                                if !first_error = None then first_error := Some e)))
              end)
            (copy_ranges ~size ~part_size));
      (match !first_error with
      | Some e ->
          abort_multipart t ~bucket:dst_bucket ~key:dst_key ~upload_id;
          Error e
      | None ->
          let parts = List.sort (fun (a, _) (b, _) -> compare a b) !results in
          complete_multipart t ~bucket:dst_bucket ~key:dst_key ~upload_id ~parts)

let copy_object t ~src_bucket ~src_key ~dst_bucket ~dst_key ?content_type
    ?(metadata = []) ?(part_size = 512 * 1024 * 1024)
    ?(multipart_threshold = 5 * 1024 * 1024 * 1024) ?(max_concurrency = 4) () =
  (* HEAD the source to learn its size (to pick single vs multipart) and its
     metadata (so a multipart copy can preserve it, as a single copy would). *)
  match head_object t ~bucket:src_bucket ~key:src_key with
  | Error _ as e -> e
  | Ok md ->
      if md.content_length <= multipart_threshold then
        copy_object_single t ~src_bucket ~src_key ~dst_bucket ~dst_key
          ?content_type ~metadata ()
      else if part_count ~size:md.content_length ~part_size > max_upload_parts
      then Error (too_many_parts_error ~size:md.content_length ~part_size)
      else
        let content_type =
          match content_type with Some _ as c -> c | None -> md.content_type
        in
        let metadata = if metadata = [] then md.user_metadata else metadata in
        multipart_copy t ~src_bucket ~src_key ~dst_bucket ~dst_key ~content_type
          ~metadata ~part_size ~max_concurrency ~size:md.content_length
