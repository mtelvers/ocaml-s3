type tree =
  | Element of string * tree list
  | Data of string

let parse_string s =
  let input = Xmlm.make_input ~strip:true (`String (0, s)) in
  let el ((_ns, local), _attrs) children = Element (local, children) in
  let data d = Data d in
  try
    let _dtd, tree = Xmlm.input_doc_tree ~el ~data input in
    Some tree
  with Xmlm.Error _ -> None

let text = function
  | Data d -> d
  | Element (_, children) ->
      children
      |> List.filter_map (function Data d -> Some d | Element _ -> None)
      |> String.concat ""

let rec find_first local tree =
  match tree with
  | Data _ -> None
  | Element (name, children) ->
      if String.equal name local then Some tree
      else List.find_map (find_first local) children

let find_text local tree = Option.map text (find_first local tree)

let find_all local tree =
  let acc = ref [] in
  let rec go tree =
    match tree with
    | Data _ -> ()
    | Element (name, children) ->
        if String.equal name local then acc := tree :: !acc;
        List.iter go children
  in
  go tree;
  List.rev !acc
