// Entry point for the UniFFI binding generator. Invoked as
// `cargo run --bin uniffi-bindgen -- generate --library <lib> --language kotlin`
// to emit the Kotlin glue under `uniffi.outline_android`.
fn main() {
    uniffi::uniffi_bindgen_main()
}
