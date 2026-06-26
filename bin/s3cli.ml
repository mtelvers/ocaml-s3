(* s3cli — a small S3 / Ceph RGW command-line client built on the [s3] library.

   It deliberately mirrors a useful subset of the s5cmd / aws-cli surface:
   listing (paginated), copying in either direction, and removing objects.
   Connection settings are resolved from flags, environment variables, or an
   AWS-style profile in ~/.aws, in that order of precedence. *)

open Cmdliner

(* ---------------------------------------------------------------------- *)
(* AWS-style ~/.aws/{credentials,config} parsing                          *)
(* ---------------------------------------------------------------------- *)

(* INI parsing lives in the library ({!S3.Credentials.parse_ini}) so the
   credentials and config files are read by a single parser, and empty values
   are treated as absent consistently ({!S3.Credentials.getenv}). *)

let home () = Option.value ~default:"." (Sys.getenv_opt "HOME")

(* ---------------------------------------------------------------------- *)
(* Connection settings                                                    *)
(* ---------------------------------------------------------------------- *)

(* Raw connection options as parsed from the command line. *)
type common = {
  endpoint : string option;
  profile : string option;
  region : string option;
  access_key : string option;
  secret_key : string option;
  no_sign : bool;
  no_verify : bool;
  ca_bundle : string option;
}

(* A fully-resolved connection. [credentials = None] is anonymous mode. *)
type conn = {
  endpoint : string;
  region : string;
  credentials : S3.Credentials.t option;
  tls : S3.Client.tls_verification;
  max_connections : int;
}

(* Precedence: explicit flag, then environment, then the selected ~/.aws
   profile, then a built-in default where one is sensible. Endpoint and region
   come from the [config] file; credentials are resolved by the library's
   provider chain (env, then the credentials file), with explicit
   --access-key/--secret-key taking priority. *)
let resolve (c : common) : (conn, string) result =
  let getenv = S3.Credentials.getenv in
  let profile =
    match c.profile with
    | Some p -> p
    | None -> Option.value ~default:"default" (getenv "AWS_PROFILE")
  in
  let config =
    S3.Credentials.parse_ini (Filename.concat (home ()) ".aws/config")
  in
  let ( <|> ) a b = match a with Some _ -> a | None -> b in
  let endpoint =
    c.endpoint
    <|> getenv "AWS_ENDPOINT_URL"
    <|> S3.Credentials.ini_get config ~section:profile ~key:"endpoint_url"
  in
  let region =
    c.region
    <|> getenv "AWS_REGION"
    <|> S3.Credentials.ini_get config ~section:profile ~key:"region"
    <|> Some "us-east-1"
  in
  let credentials =
    if c.no_sign then Ok None
    else
      match (c.access_key, c.secret_key) with
      | Some access_key, Some secret_key ->
          Ok
            (Some
               {
                 S3.Credentials.access_key;
                 secret_key;
                 session_token = getenv "AWS_SESSION_TOKEN";
               })
      | Some _, None | None, Some _ ->
          Error "both --access-key and --secret-key are required together"
      | None, None ->
          Result.map Option.some (S3.Credentials.default_chain ~profile ())
  in
  (* --ca-bundle takes precedence over --no-verify; default is system trust. *)
  let tls =
    match (c.ca_bundle, c.no_verify) with
    | Some path, _ -> S3.Client.Ca_file path
    | None, true -> S3.Client.No_verification
    | None, false -> S3.Client.System_trust
  in
  match (endpoint, credentials) with
  | None, _ ->
      Error
        "no endpoint: pass --endpoint-url, set AWS_ENDPOINT_URL, or add \
         endpoint_url to the profile"
  | _, Error m -> Error m
  | Some endpoint, Ok credentials ->
      Ok { endpoint; region = Option.get region; credentials; tls; max_connections = 8 }

(* ---------------------------------------------------------------------- *)
(* Helpers                                                                *)
(* ---------------------------------------------------------------------- *)

let die fmt = Fmt.kpf (fun _ -> exit 1) Fmt.stderr ("s3cli: " ^^ fmt ^^ "@.")

(* Parse a byte size: a number with an optional unit suffix. Units are binary
   (K = 1024, M = 1024^2, G = 1024^3); "MB" and "MiB" are treated the same. *)
let parse_size s =
  let s = String.trim s in
  let n = String.length s in
  let i = ref 0 in
  while !i < n && s.[!i] >= '0' && s.[!i] <= '9' do
    incr i
  done;
  if !i = 0 then None
  else
    match int_of_string_opt (String.sub s 0 !i) with
    | None -> None
    | Some num -> (
        let unit = String.lowercase_ascii (String.trim (String.sub s !i (n - !i))) in
        let mult =
          match unit with
          | "" | "b" -> Some 1
          | "k" | "kb" | "kib" -> Some 1024
          | "m" | "mb" | "mib" -> Some (1024 * 1024)
          | "g" | "gb" | "gib" -> Some (1024 * 1024 * 1024)
          | _ -> None
        in
        Option.map (fun m -> num * m) mult)

let size_conv =
  let parse s =
    match parse_size s with
    | Some n when n > 0 -> Ok n
    | _ -> Error (`Msg (Printf.sprintf "invalid size %S (e.g. 8MiB, 64MB, 1G)" s))
  in
  Cmdliner.Arg.conv ~docv:"SIZE" (parse, Format.pp_print_int)

let is_s3 s = String.length s >= 5 && String.sub s 0 5 = "s3://"

(* Parse "s3://bucket/key..." into (bucket, key); key is "" if absent. *)
let parse_s3_uri s =
  if not (is_s3 s) then die "%S is not an s3:// URI" s
  else
    let rest = String.sub s 5 (String.length s - 5) in
    match String.index_opt rest '/' with
    | None -> (rest, "")
    | Some i ->
        ( String.sub rest 0 i,
          String.sub rest (i + 1) (String.length rest - i - 1) )

let local_path env s =
  if Filename.is_relative s then Eio.Path.(Eio.Stdenv.cwd env / s)
  else Eio.Path.(Eio.Stdenv.fs env / s)

let with_client conn f =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let net = Eio.Stdenv.net env and clock = Eio.Stdenv.clock env in
  let cfg =
    S3.Client.make_config ~endpoint:conn.endpoint ~region:conn.region
      ?credentials:conn.credentials ~tls_verification:conn.tls
      ~max_connections:conn.max_connections ()
  in
  f env (S3.Client.create ~sw ~net ~clock cfg)

let resolve_or_die common =
  match resolve common with Ok c -> c | Error m -> die "%s" m

(* ---------------------------------------------------------------------- *)
(* Commands                                                               *)
(* ---------------------------------------------------------------------- *)

let ls common ~long uri =
  let conn = resolve_or_die common in
  let bucket, key = parse_s3_uri uri in
  (* A trailing "*" is treated as "everything under this prefix", like a shell
     glob in s5cmd. We do not support mid-string globs. *)
  let key =
    if String.length key > 0 && key.[String.length key - 1] = '*' then
      String.sub key 0 (String.length key - 1)
    else key
  in
  let prefix = if key = "" then None else Some key in
  with_client conn (fun _env client ->
      let buf = Buffer.create (64 * 1024) in
      let flush_buf () =
        output_string stdout (Buffer.contents buf);
        Buffer.clear buf
      in
      let emit (e : S3.Client.entry) =
        (if long then
           Buffer.add_string buf
             (Printf.sprintf "%-24s %12d  %s\n"
                (Option.value ~default:"" e.last_modified)
                e.size e.key)
         else begin
           Buffer.add_string buf e.key;
           Buffer.add_char buf '\n'
         end);
        if Buffer.length buf >= 64 * 1024 then flush_buf ()
      in
      match S3.Client.iter_objects client ~bucket ?prefix ~f:emit () with
      | Ok _n ->
          flush_buf ();
          flush stdout
      | Error e ->
          flush_buf ();
          flush stdout;
          die "%a" S3.Client.pp_error e)

let basename key =
  match String.rindex_opt key '/' with
  | None -> key
  | Some i -> String.sub key (i + 1) (String.length key - i - 1)

(* Parse a [KEY=VALUE] metadata argument. *)
let parse_kv s =
  match String.index_opt s '=' with
  | Some i -> (String.sub s 0 i, String.sub s (i + 1) (String.length s - i - 1))
  | None -> die "invalid --metadata %S (expected KEY=VALUE)" s

let cp common ~part_size ~concurrency ~metadata src dst =
  let conn = resolve_or_die common in
  let metadata = List.map parse_kv metadata in
  match (is_s3 src, is_s3 dst) with
  | true, false ->
      (* download (part_size/concurrency do not apply) *)
      let bucket, key = parse_s3_uri src in
      if key = "" then die "source %S has no object key" src;
      with_client conn (fun env client ->
          let dst_path =
            match Eio.Path.kind ~follow:true (local_path env dst) with
            | `Directory -> local_path env (Filename.concat dst (basename key))
            | _ -> local_path env dst
          in
          match S3.Client.get_to_file client ~bucket ~key ~path:dst_path with
          | Ok () -> Fmt.pr "downloaded s3://%s/%s -> %s@." bucket key dst
          | Error e -> die "%a" S3.Client.pp_error e)
  | false, true ->
      (* upload: grow the connection pool to admit the requested concurrency. *)
      let conn =
        match concurrency with
        | Some c -> { conn with max_connections = max conn.max_connections c }
        | None -> conn
      in
      let bucket, key = parse_s3_uri dst in
      with_client conn (fun env client ->
          let src_path = local_path env src in
          let key =
            if key = "" || key.[String.length key - 1] = '/' then
              key ^ basename src
            else key
          in
          match
            S3.Client.put_file client ~bucket ~key ~metadata ?part_size
              ?max_concurrency:concurrency ~path:src_path ()
          with
          | Ok etag ->
              Fmt.pr "uploaded %s -> s3://%s/%s (etag %s)@." src bucket key etag
          | Error e -> die "%a" S3.Client.pp_error e)
  | true, true ->
      (* server-side copy (same endpoint) *)
      let src_bucket, src_key = parse_s3_uri src in
      let dst_bucket, dst_key = parse_s3_uri dst in
      if src_key = "" then die "source %S has no object key" src;
      let dst_key = if dst_key = "" || dst_key.[String.length dst_key - 1] = '/'
                    then dst_key ^ basename src_key else dst_key in
      with_client conn (fun _env client ->
          match
            S3.Client.copy_object client ~src_bucket ~src_key ~dst_bucket
              ~dst_key ~metadata ?part_size ?max_concurrency:concurrency ()
          with
          | Ok etag ->
              Fmt.pr "copied s3://%s/%s -> s3://%s/%s (etag %s)@." src_bucket
                src_key dst_bucket dst_key etag
          | Error e -> die "%a" S3.Client.pp_error e)
  | false, false -> die "exactly one of SRC and DST must be an s3:// URI"

let rm common uri =
  let conn = resolve_or_die common in
  let bucket, key = parse_s3_uri uri in
  if key = "" then die "%S has no object key" uri;
  with_client conn (fun _env client ->
      match S3.Client.delete_object client ~bucket ~key with
      | Ok () -> Fmt.pr "deleted s3://%s/%s@." bucket key
      | Error e -> die "%a" S3.Client.pp_error e)

let stat common uri =
  let conn = resolve_or_die common in
  let bucket, key = parse_s3_uri uri in
  if key = "" then die "%S has no object key" uri;
  with_client conn (fun _env client ->
      match S3.Client.head_object client ~bucket ~key with
      | Error e -> die "%a" S3.Client.pp_error e
      | Ok md ->
          let line label = function Some v -> Fmt.pr "%-14s %s@." label v | None -> () in
          Fmt.pr "%-14s %d@." "size" md.S3.Client.content_length;
          line "etag" md.S3.Client.etag;
          line "last-modified" md.S3.Client.last_modified;
          line "content-type" md.S3.Client.content_type;
          List.iter
            (fun (k, v) -> Fmt.pr "%-14s %s@." ("meta." ^ k) v)
            md.S3.Client.user_metadata)

let mb common uri =
  let conn = resolve_or_die common in
  let bucket, _ = parse_s3_uri uri in
  with_client conn (fun _env client ->
      match S3.Client.create_bucket client ~bucket with
      | Ok () -> Fmt.pr "created s3://%s@." bucket
      | Error e -> die "%a" S3.Client.pp_error e)

let rb common uri =
  let conn = resolve_or_die common in
  let bucket, _ = parse_s3_uri uri in
  with_client conn (fun _env client ->
      match S3.Client.delete_bucket client ~bucket with
      | Ok () -> Fmt.pr "removed s3://%s@." bucket
      | Error e -> die "%a" S3.Client.pp_error e)

(* ---------------------------------------------------------------------- *)
(* Cmdliner wiring                                                        *)
(* ---------------------------------------------------------------------- *)

let endpoint_arg =
  let doc = "Endpoint URL of the S3 / RGW server, e.g. $(b,http://host:8080)." in
  Arg.(
    value
    & opt (some string) None
    & info [ "endpoint-url" ] ~docv:"URL"
        ~env:(Cmd.Env.info "AWS_ENDPOINT_URL") ~doc)

let profile_arg =
  let doc = "AWS profile to read from ~/.aws/{credentials,config}." in
  Arg.(
    value
    & opt (some string) None
    & info [ "profile" ] ~docv:"NAME" ~env:(Cmd.Env.info "AWS_PROFILE") ~doc)

let region_arg =
  let doc = "Signing region (default: profile region or $(b,us-east-1))." in
  Arg.(
    value
    & opt (some string) None
    & info [ "region" ] ~docv:"REGION" ~env:(Cmd.Env.info "AWS_REGION") ~doc)

let access_key_arg =
  let doc = "Access key id (overrides env and profile)." in
  Arg.(
    value
    & opt (some string) None
    & info [ "access-key" ] ~docv:"KEY"
        ~env:(Cmd.Env.info "AWS_ACCESS_KEY_ID") ~doc)

let secret_key_arg =
  let doc = "Secret access key (overrides env and profile)." in
  Arg.(
    value
    & opt (some string) None
    & info [ "secret-key" ] ~docv:"KEY"
        ~env:(Cmd.Env.info "AWS_SECRET_ACCESS_KEY") ~doc)

let no_sign_arg =
  let doc =
    "Make unsigned, anonymous requests (no credentials sent), for reading \
     public buckets. Takes precedence over any supplied or configured \
     credentials."
  in
  Arg.(value & flag & info [ "no-sign-request" ] ~doc)

let no_verify_arg =
  let doc =
    "Do not verify the server's TLS certificate (insecure; for https \
     endpoints with self-signed certificates)."
  in
  Arg.(value & flag & info [ "no-verify" ] ~doc)

let ca_bundle_arg =
  let doc =
    "Verify the server's TLS certificate against the PEM trust anchors in \
     $(docv) instead of the system store. Takes precedence over $(b,--no-verify)."
  in
  Arg.(
    value
    & opt (some file) None
    & info [ "ca-bundle" ] ~docv:"FILE" ~env:(Cmd.Env.info "AWS_CA_BUNDLE") ~doc)

(* All shared connection options, gathered into a single value passed to every
   command. *)
let common_term =
  let make endpoint profile region access_key secret_key no_sign no_verify
      ca_bundle =
    {
      endpoint;
      profile;
      region;
      access_key;
      secret_key;
      no_sign;
      no_verify;
      ca_bundle;
    }
  in
  Term.(
    const make $ endpoint_arg $ profile_arg $ region_arg $ access_key_arg
    $ secret_key_arg $ no_sign_arg $ no_verify_arg $ ca_bundle_arg)

let ls_cmd =
  let uri =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"S3_URI"
          ~doc:"Bucket/prefix to list, e.g. $(b,s3://bucket/prefix/) (a \
                trailing $(b,*) is accepted).")
  in
  let long =
    let doc =
      "Long format: one line per object with $(b,last-modified), size and key \
       (instead of just the key)."
    in
    Arg.(value & flag & info [ "l"; "long" ] ~doc)
  in
  let doc = "List object keys under a bucket/prefix (one per line)." in
  let man =
    [
      `S Manpage.s_description;
      `P "Follows continuation tokens to list every matching key across all \
          pages, printing one key per line for easy piping (e.g. $(b,| wc -l)). \
          With $(b,-l), prints last-modified, size and key instead.";
      `S Manpage.s_examples;
      `P "s3cli --profile ceph-tessera ls s3://bucket/prefix/";
      `P "s3cli ls -l s3://bucket/prefix/";
    ]
  in
  Cmd.v (Cmd.info "ls" ~doc ~man)
    Term.(
      const (fun common long uri -> ls common ~long uri)
      $ common_term $ long $ uri)

let cp_cmd =
  let src =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"SRC" ~doc:"Source: a local path or an s3:// URI.")
  in
  let dst =
    Arg.(
      required
      & pos 1 (some string) None
      & info [] ~docv:"DST" ~doc:"Destination: a local path or an s3:// URI.")
  in
  let part_size =
    let doc =
      "Multipart part size for uploads, e.g. $(b,8MiB), $(b,64MB), $(b,1G) \
       (default 8MiB; minimum 5MiB per the S3 spec). Ignored for downloads."
    in
    Arg.(value & opt (some size_conv) None & info [ "part-size" ] ~docv:"SIZE" ~doc)
  in
  let concurrency =
    let doc =
      "Number of multipart parts to upload concurrently (default 4). Also \
       grows the connection pool to match. Ignored for downloads."
    in
    Arg.(value & opt (some int) None & info [ "concurrency" ] ~docv:"N" ~doc)
  in
  let metadata =
    let doc =
      "User metadata to attach, as $(b,KEY=VALUE) (sent as $(b,x-amz-meta-KEY)); \
       repeatable. Applies to uploads and s3->s3 copies."
    in
    Arg.(value & opt_all string [] & info [ "metadata" ] ~docv:"KEY=VALUE" ~doc)
  in
  let doc = "Copy a single object up to or down from S3." in
  let man =
    [
      `S Manpage.s_description;
      `P "The direction is inferred from which of SRC and DST is an s3:// URI: \
          local->s3 uploads, s3->local downloads, and s3->s3 performs a \
          server-side copy (same endpoint, bytes never transit the client). \
          Large uploads automatically use a multipart upload; \
          $(b,--part-size) and $(b,--concurrency) tune its throughput.";
      `S Manpage.s_examples;
      `P "s3cli cp ./big.bin s3://bucket/big.bin";
      `P "s3cli cp --part-size 64MB --concurrency 8 ./big.bin s3://bucket/big.bin";
      `P "s3cli cp --metadata sha256=… ./grid.npy s3://bucket/grid.npy";
      `P "s3cli cp s3://bucket/big.bin ./big.bin";
      `P "s3cli cp s3://bucket/a.bin s3://bucket/b.bin";
    ]
  in
  Cmd.v (Cmd.info "cp" ~doc ~man)
    Term.(
      const (fun common part_size concurrency metadata src dst ->
          cp common ~part_size ~concurrency ~metadata src dst)
      $ common_term $ part_size $ concurrency $ metadata $ src $ dst)

let rm_cmd =
  let uri =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"S3_URI" ~doc:"Object to delete, e.g. s3://bucket/key.")
  in
  let doc = "Delete a single object." in
  Cmd.v (Cmd.info "rm" ~doc) Term.(const rm $ common_term $ uri)

let stat_cmd =
  let uri =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"S3_URI" ~doc:"Object to inspect, e.g. s3://bucket/key.")
  in
  let doc = "Show an object's size, ETag, timestamps and user metadata." in
  Cmd.v (Cmd.info "stat" ~doc) Term.(const stat $ common_term $ uri)

let mb_cmd =
  let uri =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"S3_URI" ~doc:"Bucket to create, e.g. s3://bucket.")
  in
  let doc = "Create a bucket." in
  Cmd.v (Cmd.info "mb" ~doc) Term.(const mb $ common_term $ uri)

let rb_cmd =
  let uri =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"S3_URI" ~doc:"Bucket to remove (must be empty).")
  in
  let doc = "Remove an (empty) bucket." in
  Cmd.v (Cmd.info "rb" ~doc) Term.(const rb $ common_term $ uri)

let main_cmd =
  let doc = "S3 / Ceph RGW client" in
  let man =
    [
      `S Manpage.s_description;
      `P "$(tname) uploads, downloads and lists objects on an S3-compatible \
          server. Connection settings are taken from command-line options, \
          then environment variables, then the selected ~/.aws profile.";
    ]
  in
  Cmd.group (Cmd.info "s3cli" ~version:"0.1.0" ~doc ~man)
    [ ls_cmd; cp_cmd; rm_cmd; stat_cmd; mb_cmd; rb_cmd ]

(* Allow the shared connection options to appear *before* the subcommand
   (s5cmd / aws-cli style, e.g. [s3cli --endpoint-url URL ls ...]). cmdliner
   attaches them to each subcommand, so it would otherwise reject them ahead of
   the command name. We relocate any leading recognised global options to just
   after the subcommand, leaving every other ordering untouched. *)
let reorder_argv argv =
  let value_opts =
    [ "--endpoint-url"; "--profile"; "--region"; "--access-key";
      "--secret-key"; "--ca-bundle" ]
  in
  let flag_opts = [ "--no-sign-request"; "--no-verify" ] in
  let subcommands = [ "ls"; "cp"; "rm"; "stat"; "mb"; "rb" ] in
  let opt_name t =
    match String.index_opt t '=' with Some i -> String.sub t 0 i | None -> t
  in
  let is_value_opt t = List.mem (opt_name t) value_opts in
  match Array.to_list argv with
  | [] -> argv
  | prog :: rest ->
      (* Peel leading global options (and their values) off the front. *)
      let rec scan acc = function
        | t :: ts when is_value_opt t ->
            if String.contains t '=' then scan (t :: acc) ts
            else (
              match ts with
              | v :: ts' -> scan (v :: t :: acc) ts'
              | [] -> (List.rev (t :: acc), []))
        | t :: ts when List.mem t flag_opts -> scan (t :: acc) ts
        | remaining -> (List.rev acc, remaining)
      in
      let globals, remaining = scan [] rest in
      (match remaining with
      | sub :: after when List.mem sub subcommands ->
          Array.of_list ((prog :: sub :: globals) @ after)
      | _ -> argv)

let () = exit (Cmd.eval ~argv:(reorder_argv Sys.argv) main_cmd)
