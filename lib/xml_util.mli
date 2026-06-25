(** Minimal XML parsing helpers for S3 response bodies.

    S3 replies (multipart upload results, listings and errors) are small XML
    documents. We parse them into a simple tree and offer a couple of lookup
    helpers rather than pulling in a full data-binding layer. *)

type tree =
  | Element of string * tree list  (** Element with its {e local} name. *)
  | Data of string  (** Character data. *)

(** [parse_string s] parses [s] into a tree, or [None] if it is not well-formed
    XML. Element namespaces are discarded; only local names are kept. *)
val parse_string : string -> tree option

(** [find_text local tree] is the concatenated character data of the first
    element named [local] found in document order (depth-first), or [None]. *)
val find_text : string -> tree -> string option

(** [find_all local tree] is every element named [local] anywhere in [tree], in
    document order. *)
val find_all : string -> tree -> tree list
