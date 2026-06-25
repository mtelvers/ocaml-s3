(* Offline unit tests: SigV4 signing against the AWS published test vector,
   percent-encoding, and XML response parsing. These require no network and run
   under [dune runtest]. *)

let test_empty_payload_hash () =
  Alcotest.(check string)
    "SHA-256 of empty string"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    S3.Auth.empty_payload_hash

let test_hex_sha256 () =
  Alcotest.(check string)
    "SHA-256 of \"hello\""
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    (S3.Auth.hex_sha256 "hello")

let test_uri_encode () =
  let check ~encode_slash input expected =
    Alcotest.(check string)
      (Printf.sprintf "uri_encode ~encode_slash:%b %S" encode_slash input)
      expected
      (S3.Auth.uri_encode ~encode_slash input)
  in
  check ~encode_slash:false "/foo/bar baz" "/foo/bar%20baz";
  check ~encode_slash:true "/foo/bar" "%2Ffoo%2Fbar";
  check ~encode_slash:true "-_.~" "-_.~";
  check ~encode_slash:true "key=value&x" "key%3Dvalue%26x";
  (* UTF-8 bytes are encoded one byte at a time. *)
  check ~encode_slash:false "\xe6\x97\xa5" "%E6%97%A5"

(* AWS SigV4 test-suite "get-vanilla" known-answer, verified independently. *)
let test_sigv4_get_vanilla () =
  let credentials =
    {
      S3.Auth.access_key = "AKIDEXAMPLE";
      secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    }
  in
  let auth =
    S3.Auth.authorization_header ~credentials ~region:"us-east-1"
      ~service:"service" ~meth:"GET" ~path:"/" ~query:[]
      ~headers:
        [
          ("host", "example.amazonaws.com");
          ("x-amz-date", "20150830T123600Z");
        ]
      ~payload_hash:S3.Auth.empty_payload_hash ~amz_date:"20150830T123600Z"
  in
  Alcotest.(check string)
    "Authorization header"
    "AWS4-HMAC-SHA256 \
     Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
     SignedHeaders=host;x-amz-date, \
     Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    auth

let test_amz_date () =
  (* 2015-08-30T12:36:00Z == POSIX 1440938160. *)
  Alcotest.(check string)
    "amz_date_of_posix" "20150830T123600Z"
    (S3.Auth.amz_date_of_posix 1440938160.)

let test_parse_error () =
  let xml =
    {|<?xml version="1.0" encoding="UTF-8"?>
      <Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>
      <Key>missing.txt</Key></Error>|}
  in
  match S3.Xml_util.parse_string xml with
  | None -> Alcotest.fail "expected well-formed XML"
  | Some tree ->
      Alcotest.(check (option string))
        "Code" (Some "NoSuchKey")
        (S3.Xml_util.find_text "Code" tree);
      Alcotest.(check (option string))
        "Message"
        (Some "The specified key does not exist.")
        (S3.Xml_util.find_text "Message" tree)

let test_parse_upload_id () =
  let xml =
    {|<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key>
      <UploadId>abc-123</UploadId></InitiateMultipartUploadResult>|}
  in
  let id =
    Option.bind (S3.Xml_util.parse_string xml)
      (S3.Xml_util.find_text "UploadId")
  in
  Alcotest.(check (option string)) "UploadId" (Some "abc-123") id

let test_parse_listing () =
  let xml =
    {|<ListBucketResult><Name>b</Name>
      <Contents><Key>a.txt</Key><Size>1</Size></Contents>
      <Contents><Key>dir/b.txt</Key><Size>2</Size></Contents>
      </ListBucketResult>|}
  in
  match S3.Xml_util.parse_string xml with
  | None -> Alcotest.fail "expected well-formed XML"
  | Some tree ->
      let keys =
        S3.Xml_util.find_all "Contents" tree
        |> List.filter_map (S3.Xml_util.find_text "Key")
      in
      Alcotest.(check (list string)) "keys" [ "a.txt"; "dir/b.txt" ] keys

(* Credentials resolution from a shared credentials file (deterministic, no
   environment dependence — we pass an explicit file and profile). *)
let with_temp_file contents f =
  let path = Filename.temp_file "s3-creds" ".ini" in
  let oc = open_out path in
  output_string oc contents;
  close_out oc;
  Fun.protect ~finally:(fun () -> try Sys.remove path with _ -> ()) (fun () -> f path)

let creds_file =
  {|[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = defaultsecret

[ceph]
aws_access_key_id = AKIACEPH
aws_secret_access_key = cephsecret
aws_session_token = tok123
|}

let test_credentials_default () =
  with_temp_file creds_file @@ fun file ->
  match S3.Credentials.from_profile ~profile:"default" ~file () with
  | Error m -> Alcotest.failf "expected ok: %s" m
  | Ok c ->
      Alcotest.(check string) "access" "AKIADEFAULT" c.S3.Credentials.access_key;
      Alcotest.(check string) "secret" "defaultsecret" c.S3.Credentials.secret_key;
      Alcotest.(check (option string)) "no token" None c.S3.Credentials.session_token

let test_credentials_named_with_token () =
  with_temp_file creds_file @@ fun file ->
  match S3.Credentials.from_profile ~profile:"ceph" ~file () with
  | Error m -> Alcotest.failf "expected ok: %s" m
  | Ok c ->
      Alcotest.(check string) "access" "AKIACEPH" c.S3.Credentials.access_key;
      Alcotest.(check (option string))
        "token" (Some "tok123") c.S3.Credentials.session_token

let test_credentials_missing_profile () =
  with_temp_file creds_file @@ fun file ->
  match S3.Credentials.from_profile ~profile:"nope" ~file () with
  | Ok _ -> Alcotest.fail "expected error for missing profile"
  | Error _ -> ()

let () =
  Alcotest.run "s3-unit"
    [
      ( "credentials",
        [
          Alcotest.test_case "default profile" `Quick test_credentials_default;
          Alcotest.test_case "named profile + session token" `Quick
            test_credentials_named_with_token;
          Alcotest.test_case "missing profile errors" `Quick
            test_credentials_missing_profile;
        ] );
      ( "auth",
        [
          Alcotest.test_case "empty payload hash" `Quick
            test_empty_payload_hash;
          Alcotest.test_case "hex_sha256" `Quick test_hex_sha256;
          Alcotest.test_case "uri_encode" `Quick test_uri_encode;
          Alcotest.test_case "amz_date" `Quick test_amz_date;
          Alcotest.test_case "sigv4 get-vanilla" `Quick test_sigv4_get_vanilla;
        ] );
      ( "xml",
        [
          Alcotest.test_case "parse error" `Quick test_parse_error;
          Alcotest.test_case "parse upload id" `Quick test_parse_upload_id;
          Alcotest.test_case "parse listing" `Quick test_parse_listing;
        ] );
    ]
