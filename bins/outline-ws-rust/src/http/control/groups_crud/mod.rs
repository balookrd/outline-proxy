// TODO(Task 3): the dispatcher/handlers + `list.rs` land next and wire up
// every `payload` item (constructing `GroupPayload`/`CreateBody`/etc., calling
// `payload_to_table`/`merge_patch_into_table`/`table_to_section`, and
// importing the `table_to_json` re-export the same way `uplinks_crud::list`
// does). Until then this whole module is dead code from the crate's point of
// view outside its own tests — drop this allow once Task 3 adds the callers.
#![allow(dead_code, unused_imports)]

mod payload;

#[cfg(test)]
#[path = "tests/payload.rs"]
mod tests;
