(** AWS-style credential resolution.

    Mirrors the common provider chain: static [AWS_*] environment variables
    first, then the shared credentials file ([~/.aws/credentials], profile from
    [AWS_PROFILE] or ["default"]). Resolution is pure I/O over the filesystem and
    environment — no network — so it is independent of {!module:Client}. *)

type t = {
  access_key : string;
  secret_key : string;
  session_token : string option;
      (** Set for temporary credentials; sent as [x-amz-security-token] and
          signed. [None] for long-lived keys. *)
}

(** [from_env ()] reads [AWS_ACCESS_KEY_ID] and [AWS_SECRET_ACCESS_KEY] (and the
    optional [AWS_SESSION_TOKEN]) from the environment. [Error] with a message if
    either required variable is unset or empty. *)
val from_env : unit -> (t, string) result

(** [from_profile ?profile ?file ()] reads credentials from a shared credentials
    file ([file], default [~/.aws/credentials]) for [profile] (default:
    [AWS_PROFILE], else ["default"]). Recognises the [aws_access_key_id],
    [aws_secret_access_key] and [aws_session_token] keys. [Error] if the file or
    profile is missing, or the required keys are absent. *)
val from_profile :
  ?profile:string -> ?file:string -> unit -> (t, string) result

(** [default_chain ?profile ?file ()] tries {!from_env}, then {!from_profile}.
    Returns the first success, or the last error if both fail. *)
val default_chain :
  ?profile:string -> ?file:string -> unit -> (t, string) result
