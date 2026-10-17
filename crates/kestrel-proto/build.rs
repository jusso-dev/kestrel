fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Safety: this build script has not spawned threads, so no other thread is
    // reading the environment. prost-build discovers protoc through PROTOC.
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }
    // prost's Message derive already implements Debug.
    prost_build::Config::new()
        .type_attribute(
            "kestrel.v1.AgentConfig",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute("kestrel.v1.AgentConfig", "#[serde(default)]")
        .type_attribute(
            "kestrel.v1.CheckSpec",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "kestrel.v1.LogSpec",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "kestrel.v1.ItemSpec",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(
            &[
                "proto/kestrel.proto",
                "proto/remote.proto",
                "proto/otlp.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
