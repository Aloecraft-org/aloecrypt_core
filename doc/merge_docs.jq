# Usage: jq -s -f merge_docs.jq api_core.json api_core_docs.json > api_core_merged.json
#
# Strategy: for each module, for each array field (sz_consts, byte_aliases, empty_consts,
# structs, traits, functions), match elements by "name" and merge the doc object into
# the source object. Elements with no matching doc entry are passed through unchanged.
# The source (api_core.json) is always .[0]; docs are .[1].

.[0] as $src |
.[1] as $docs |

# Merge two arrays by "name", adding fields from $overlay items into $base items
def merge_by_name(base; overlay):
  base | map(
    . as $item |
    (overlay // [] | map(select(.name == $item.name)) | first) as $doc |
    if $doc then $item + $doc else $item end
  );

# For enums, merge top-level doc fields and nested "members" array in one pass.
def merge_enum(base; overlay):
  base | map(
    . as $item |
    (overlay // [] | map(select(.name == $item.name)) | first) as $doc |
    if $doc then
      # Merge top-level scalar doc fields without touching .members
      ($doc | del(.members)) as $doc_sans_members |
      $item + $doc_sans_members
      | if $item.members and $doc.members then
          .members = merge_by_name($item.members; $doc.members)
        else . end
    else $item end
  );

# For structs, merge top-level doc fields and nested "fields" array in one pass,
# never letting the doc's fields array overwrite the source's fields array wholesale.
def merge_struct(base; overlay):
  base | map(
    . as $item |
    (overlay // [] | map(select(.name == $item.name)) | first) as $doc |
    if $doc then
      # Merge top-level scalar doc fields (description etc.) without touching .fields
      ($doc | del(.fields)) as $doc_sans_fields |
      $item + $doc_sans_fields
      | if $item.fields and $doc.fields then
          .fields = merge_by_name($item.fields; $doc.fields)
        else . end
    else $item end
  );

def merge_trait(base; overlay):
  base | map(
    . as $item |
    (overlay // [] | map(select(.name == $item.name)) | first) as $doc |
    if $doc then
      ($doc | del(.functions)) as $doc_sans_fns |
      $item + $doc_sans_fns
      | if $item.functions and $doc.functions then
          .functions = (
            $item.functions | map(
              . as $fn |
              (($doc.functions // []) | map(select(.name == $fn.name)) | first) as $dfn |
              if $dfn then
                ($dfn | del(.params)) as $dfn_sans_params |
                $fn + $dfn_sans_params
                | if $fn.params and $dfn.params then
                    .params = merge_by_name($fn.params; $dfn.params)
                  else . end
              else $fn end
            )
          )
        else . end
    else $item end
  );

# Merge a flat array of functions (each with name/return/params),
# distinct from merge_trait which handles trait objects that *contain* a functions array.
def merge_functions(base; overlay):
  base | map(
    . as $fn |
    (overlay // [] | map(select(.name == $fn.name)) | first) as $dfn |
    if $dfn then
      ($dfn | del(.params)) as $dfn_sans_params |
      $fn + $dfn_sans_params
      | if $fn.params and $dfn.params then
          .params = merge_by_name($fn.params; $dfn.params)
        else . end
    else $fn end
  );

# Merge a single module object
def merge_module(src_mod; doc_mod):
  src_mod
  | if .sz_consts    then .sz_consts    = merge_by_name(src_mod.sz_consts;    doc_mod.sz_consts)    else . end
  | if .byte_aliases then .byte_aliases = merge_by_name(src_mod.byte_aliases; doc_mod.byte_aliases) else . end
  | if .empty_consts then .empty_consts = merge_by_name(src_mod.empty_consts; doc_mod.empty_consts) else . end
  | if .enums        then .enums        = merge_enum(src_mod.enums;           doc_mod.enums)        else . end
  | if .structs      then .structs      = merge_struct(src_mod.structs;       doc_mod.structs)      else . end
  | if .traits       then .traits       = merge_trait(src_mod.traits;         doc_mod.traits)       else . end
  | if .functions    then .functions    = merge_functions(src_mod.functions;  doc_mod.functions)    else . end
  | if .impls        then .impls        = src_mod.impls                                             else . end;

# Walk every top-level module key
$src | to_entries | map(
  . as $entry |
  ($docs[$entry.key] // {}) as $doc_mod |
  { key: $entry.key, value: merge_module($entry.value; $doc_mod) }
) | from_entries
