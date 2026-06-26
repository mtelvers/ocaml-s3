type t = {
  access_key : string;
  secret_key : string;
  session_token : string option;
}

let home () = match Sys.getenv_opt "HOME" with Some h -> h | None -> "."
let default_file () = Filename.concat (home ()) ".aws/credentials"

(* [Some v] only for a set, non-empty variable; an explicitly empty value is
   treated as unset, the same as an empty profile entry (see [non_empty]). *)
let getenv k =
  match Sys.getenv_opt k with Some "" | None -> None | Some v -> Some v

(* An empty string is treated as absent, so a blank entry never yields a
   credential (which would otherwise be signed into a malformed request). *)
let non_empty = function Some "" | None -> None | some -> some

let from_env () =
  match (getenv "AWS_ACCESS_KEY_ID", getenv "AWS_SECRET_ACCESS_KEY") with
  | Some access_key, Some secret_key ->
      Ok { access_key; secret_key; session_token = getenv "AWS_SESSION_TOKEN" }
  | _ ->
      Error
        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set in the \
         environment"

(* Parse an AWS-style INI file (shared credentials or config) into
   [section -> (key, value) list].

   Section headers spelled [NAME] and [profile NAME] both yield [NAME]: the
   config file prefixes non-default profiles with "profile ", whereas the
   credentials file does not. Blank/comment lines, and indented continuation
   lines (the nested "s3 =" sub-block and the like), are skipped. Keys appearing
   before any section header are ignored. Returns [] if the file is absent. *)
let parse_ini path =
  if not (Sys.file_exists path) then []
  else
    (* config uses "[profile NAME]"; credentials uses "[NAME]" — both yield NAME. *)
    let section_name trimmed =
      let name = String.trim (String.sub trimmed 1 (String.length trimmed - 2)) in
      match String.split_on_char ' ' name with [ "profile"; n ] -> n | _ -> name
    in
    let add_kv kvs line =
      match String.index_opt line '=' with
      | None -> kvs
      | Some i ->
          let k = String.trim (String.sub line 0 i) in
          let v = String.trim (String.sub line (i + 1) (String.length line - i - 1)) in
          (k, v) :: kvs
    in
    (* Fold lines into [(completed sections, current (name, kvs))]; close the
       open section at the end. Lists are accumulated reversed, then flipped. *)
    let step (sections, cur) line =
      let trimmed = String.trim line in
      let indented = line <> "" && (line.[0] = ' ' || line.[0] = '\t') in
      if trimmed = "" || trimmed.[0] = '#' || trimmed.[0] = ';' then (sections, cur)
      else if trimmed.[0] = '[' && trimmed.[String.length trimmed - 1] = ']' then
        let sections = match cur with Some s -> s :: sections | None -> sections in
        (sections, Some (section_name trimmed, []))
      else
        match cur with
        | Some (name, kvs) when not indented -> (sections, Some (name, add_kv kvs line))
        | _ -> (sections, cur)
    in
    let sections, cur =
      In_channel.with_open_bin path In_channel.input_lines
      |> List.fold_left step ([], None)
    in
    (match cur with Some s -> s :: sections | None -> sections)
    |> List.rev_map (fun (name, kvs) -> (name, List.rev kvs))

let ini_get sections ~section ~key =
  Option.bind (List.assoc_opt section sections) (List.assoc_opt key)

let from_profile ?profile ?file () =
  let profile =
    match profile with
    | Some p -> p
    | None -> Option.value ~default:"default" (getenv "AWS_PROFILE")
  in
  let file = match file with Some f -> f | None -> default_file () in
  match List.assoc_opt profile (parse_ini file) with
  | None -> Error (Printf.sprintf "profile %S not found in %s" profile file)
  | Some kvs -> (
      let get k = non_empty (List.assoc_opt k kvs) in
      match (get "aws_access_key_id", get "aws_secret_access_key") with
      | Some access_key, Some secret_key ->
          Ok { access_key; secret_key; session_token = get "aws_session_token" }
      | _ ->
          Error
            (Printf.sprintf
               "profile %S in %s is missing aws_access_key_id / \
                aws_secret_access_key"
               profile file))

let default_chain ?profile ?file () =
  match from_env () with
  | Ok _ as ok -> ok
  | Error _ -> from_profile ?profile ?file ()
