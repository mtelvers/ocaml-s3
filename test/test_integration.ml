(* Integration tests against a live S3-compatible server (developed against
   MinIO and Ceph RGW). These are driven by environment variables and are
   skipped (exit 0) when [S3_ENDPOINT] is unset, so they never run under the
   offline [dune runtest]. Run the built executable directly:

     S3_ENDPOINT=http://localhost:9000 \
     S3_ACCESS_KEY=... S3_SECRET_KEY=... \
     ./_build/default/test/test_integration.exe

   Optional: S3_REGION (default us-east-1), S3_LARGE_SIZE_MB (default 100). *)

let getenv = Sys.getenv_opt
let ( / ) = Eio.Path.( / )

let or_fail label = function
  | Ok v -> v
  | Error e -> Alcotest.failf "%s: %a" label S3.Client.pp_error e

(* Stream a file's SHA-256 so we can verify large round-trips without holding
   the whole object in memory. *)
let sha256_file path =
  Eio.Path.with_open_in path @@ fun flow ->
  let ctx = ref Digestif.SHA256.empty in
  let cs = Cstruct.create 65536 in
  (try
     while true do
       let n = Eio.Flow.single_read flow cs in
       ctx :=
         Digestif.SHA256.feed_string !ctx (Cstruct.to_string (Cstruct.sub cs 0 n))
     done
   with End_of_file -> ());
  Digestif.SHA256.(to_hex (get !ctx))

(* Generate a file of [size] bytes with non-trivial, deterministic content. *)
let make_file path size =
  Eio.Path.with_open_out ~create:(`Or_truncate 0o644) path @@ fun sink ->
  let block = 1024 * 1024 in
  let chunk = String.init block (fun i -> Char.chr ((i * 31) land 0xff)) in
  let written = ref 0 in
  while !written < size do
    let n = min block (size - !written) in
    Eio.Flow.copy_string (String.sub chunk 0 n) sink;
    written := !written + n
  done

let () =
  match getenv "S3_ENDPOINT" with
  | None ->
      print_endline
        "S3_ENDPOINT not set; skipping integration tests. Set S3_ENDPOINT, \
         S3_ACCESS_KEY and S3_SECRET_KEY to run them.";
      exit 0
  | Some endpoint ->
      let access_key = Option.value ~default:"minioadmin" (getenv "S3_ACCESS_KEY") in
      let secret_key = Option.value ~default:"minioadmin" (getenv "S3_SECRET_KEY") in
      let region = getenv "S3_REGION" in
      let large_mb =
        match getenv "S3_LARGE_SIZE_MB" with
        | Some s -> ( try int_of_string s with _ -> 100)
        | None -> 100
      in
      Eio_main.run @@ fun env ->
      Eio.Switch.run @@ fun sw ->
      let net = Eio.Stdenv.net env in
      let clock = Eio.Stdenv.clock env in
      let fs = Eio.Stdenv.fs env in
      let credentials =
        { S3.Credentials.access_key; secret_key; session_token = None }
      in
      let config =
        S3.Client.make_config ?region ~endpoint ~credentials ()
      in
      let client = S3.Client.create ~sw ~net ~clock config in
      let bucket = Printf.sprintf "s3test-%d" (Unix.getpid ()) in
      let tmp = fs / Filename.get_temp_dir_name () / bucket in
      Eio.Path.mkdirs ~exists_ok:true ~perm:0o755 tmp;

      let test_bucket_lifecycle () =
        or_fail "create_bucket" (S3.Client.create_bucket client ~bucket);
        Alcotest.(check bool)
          "bucket exists" true
          (or_fail "bucket_exists" (S3.Client.bucket_exists client ~bucket))
      in

      let test_put_get_string () =
        let key = "hello.txt" in
        let body = "Hello, S3 from Eio!" in
        let etag =
          or_fail "put_string"
            (S3.Client.put_string client ~bucket ~key ~content_type:"text/plain"
               ~metadata:[ ("author", "mtelvers"); ("purpose", "test") ]
               body)
        in
        Alcotest.(check bool) "etag returned" true (String.length etag > 0);
        let got = or_fail "get_string" (S3.Client.get_string client ~bucket ~key ()) in
        Alcotest.(check string) "round-trip body" body got
      in

      let test_head_metadata () =
        let key = "hello.txt" in
        let md = or_fail "head_object" (S3.Client.head_object client ~bucket ~key) in
        Alcotest.(check int)
          "content_length" (String.length "Hello, S3 from Eio!")
          md.S3.Client.content_length;
        Alcotest.(check (option string))
          "content_type" (Some "text/plain") md.S3.Client.content_type;
        let user = List.sort compare md.S3.Client.user_metadata in
        Alcotest.(check (list (pair string string)))
          "user metadata"
          [ ("author", "mtelvers"); ("purpose", "test") ]
          user
      in

      let test_list () =
        let keys = or_fail "list_objects" (S3.Client.list_objects client ~bucket ()) in
        Alcotest.(check bool)
          "listing contains hello.txt" true
          (List.mem "hello.txt" keys);
        (* The enriched entry carries the object size. *)
        let page =
          or_fail "list_page" (S3.Client.list_page client ~bucket ~prefix:"hello.txt" ())
        in
        match List.find_opt (fun (e : S3.Client.entry) -> e.key = "hello.txt") page.objects with
        | Some e ->
            Alcotest.(check int)
              "entry size" (String.length "Hello, S3 from Eio!") e.S3.Client.size
        | None -> Alcotest.fail "hello.txt not in page objects"
      in

      let test_missing_key () =
        match S3.Client.get_string client ~bucket ~key:"does-not-exist" () with
        | Ok _ -> Alcotest.fail "expected error for missing key"
        | Error e -> Alcotest.(check int) "404 status" 404 e.S3.Client.http_status
      in

      let test_delete () =
        or_fail "delete_object" (S3.Client.delete_object client ~bucket ~key:"hello.txt");
        match S3.Client.head_object client ~bucket ~key:"hello.txt" with
        | Ok _ -> Alcotest.fail "object should be gone"
        | Error e -> Alcotest.(check int) "404 after delete" 404 e.S3.Client.http_status
      in

      let test_large_multipart () =
        let size = large_mb * 1024 * 1024 in
        let src = tmp / "large.bin" in
        let dst = tmp / "large.out" in
        make_file src size;
        let src_sha = sha256_file src in
        let key = "large.bin" in
        (* Mirror genesis: a base64 sha256 in user metadata on a multipart
           upload, then read it back on HEAD. Base64 padding/`+`/`/` exercise
           header signing/transport. *)
        let meta_sha = "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" in
        let etag =
          or_fail "put_file"
            (S3.Client.put_file client ~bucket ~key
               ~content_type:"application/octet-stream"
               ~metadata:[ ("sha256", meta_sha) ] ~path:src ())
        in
        Alcotest.(check bool) "multipart etag returned" true
          (String.length etag > 0);
        let md = or_fail "head large" (S3.Client.head_object client ~bucket ~key) in
        Alcotest.(check int) "large content_length" size md.S3.Client.content_length;
        Alcotest.(check (option string))
          "multipart user metadata round-trip" (Some meta_sha)
          (List.assoc_opt "sha256" md.S3.Client.user_metadata);
        or_fail "get_to_file" (S3.Client.get_to_file client ~bucket ~key ~path:dst);
        Alcotest.(check string)
          "large round-trip sha256" src_sha (sha256_file dst);
        or_fail "delete large" (S3.Client.delete_object client ~bucket ~key)
      in

      (* Force the multipart-copy (UploadPartCopy) path with a small object by
         setting a low threshold and 5 MiB parts (S3's minimum part size). *)
      let test_multipart_copy () =
        let size = (12 * 1024 * 1024) + 7 in
        let src = tmp / "cpsrc.bin" in
        let dst = tmp / "cpsrc.out" in
        make_file src size;
        let src_sha = sha256_file src in
        let src_key = "copy/src.bin" and dst_key = "copy/dst.bin" in
        let _ : string =
          or_fail "put copy source"
            (S3.Client.put_file client ~bucket ~key:src_key
               ~content_type:"application/octet-stream" ~path:src ())
        in
        let etag =
          or_fail "multipart copy"
            (S3.Client.copy_object client ~src_bucket:bucket ~src_key
               ~dst_bucket:bucket ~dst_key
               ~multipart_threshold:(5 * 1024 * 1024)
               ~part_size:(5 * 1024 * 1024) ())
        in
        Alcotest.(check bool) "copy etag returned" true (String.length etag > 0);
        let md =
          or_fail "head copy dst" (S3.Client.head_object client ~bucket ~key:dst_key)
        in
        Alcotest.(check int) "copy content_length" size md.S3.Client.content_length;
        or_fail "get copy dst"
          (S3.Client.get_to_file client ~bucket ~key:dst_key ~path:dst);
        Alcotest.(check string) "copy sha256" src_sha (sha256_file dst);
        or_fail "delete copy src" (S3.Client.delete_object client ~bucket ~key:src_key);
        or_fail "delete copy dst" (S3.Client.delete_object client ~bucket ~key:dst_key)
      in

      let test_cleanup () =
        or_fail "delete_bucket" (S3.Client.delete_bucket client ~bucket)
      in

      Fun.protect
        ~finally:(fun () -> try Eio.Path.rmtree tmp with _ -> ())
        (fun () ->
          Alcotest.run ~and_exit:true "s3-integration"
            [
              ( "lifecycle",
                [
                  Alcotest.test_case "create bucket" `Quick
                    test_bucket_lifecycle;
                  Alcotest.test_case "put/get string" `Quick test_put_get_string;
                  Alcotest.test_case "head metadata" `Quick test_head_metadata;
                  Alcotest.test_case "list objects" `Quick test_list;
                  Alcotest.test_case "missing key" `Quick test_missing_key;
                  Alcotest.test_case "delete object" `Quick test_delete;
                  Alcotest.test_case
                    (Printf.sprintf "multipart %d MiB round-trip" large_mb)
                    `Slow test_large_multipart;
                  Alcotest.test_case "multipart server-side copy" `Slow
                    test_multipart_copy;
                  Alcotest.test_case "delete bucket" `Quick test_cleanup;
                ] );
            ])
