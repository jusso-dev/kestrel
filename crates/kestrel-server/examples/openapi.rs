fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&kestrel_server::api::openapi_value()).unwrap()
    );
}
