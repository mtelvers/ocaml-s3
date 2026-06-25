type t = {
  access_key : string;
  secret_key : string;
  session_token : string option;
}

let home () = match Sys.getenv_opt "HOME" with Some h -> h | None -> "."
let default_file () = Filename.concat (home ()) ".aws/credentials"

(* [Some v] only for a set, non-empty variable. *)
let getenv k =
  match Sys.getenv_opt k with Some "" | None -> None | Some v -> Some v

let from_env () =
  match (getenv "AWS_ACCESS_KEY_ID", getenv "AWS_SECRET_ACCESS_KEY") with
  | Some access_key, Some secret_key ->
      Ok { access_key; secret_key; session_token = getenv "AWS_SESSION_TOKEN" }
  | _ ->
      Error
        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set in the \
         environment"

(* Read the [section] of an INI file into a key/value assoc, or [None] if the
   file or section is absent. Only top-level "key = value" lines are kept. *)
let read_section file ~section =
  if not (Sys.file_exists file) then None
  else
    let ic = open_in file in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
        let in_target = ref false and seen = ref false and kvs = ref [] in
        (try
           while true do
             let line = String.trim (input_line ic) in
             if line = "" || line.[0] = '#' || line.[0] = ';' then ()
             else if line.[0] = '[' && line.[String.length line - 1] = ']' then begin
               let name = String.trim (String.sub line 1 (String.length line - 2)) in
               in_target := String.equal name section;
               if !in_target then seen := true
             end
             else if !in_target then
               match String.index_opt line '=' with
               | Some i ->
                   let k = String.trim (String.sub line 0 i) in
                   let v =
                     String.trim (String.sub line (i + 1) (String.length line - i - 1))
                   in
                   kvs := (k, v) :: !kvs
               | None -> ()
           done
         with End_of_file -> ());
        if !seen then Some (List.rev !kvs) else None)

let from_profile ?profile ?file () =
  let profile =
    match profile with
    | Some p -> p
    | None -> ( match getenv "AWS_PROFILE" with Some p -> p | None -> "default")
  in
  let file = match file with Some f -> f | None -> default_file () in
  match read_section file ~section:profile with
  | None ->
      Error (Printf.sprintf "profile %S not found in %s" profile file)
  | Some kvs -> (
      let get k = List.assoc_opt k kvs in
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
