fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Safety: this build script has not spawned threads, so no other thread is
    // reading the environment. prost-build discovers protoc through PROTOC.
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }
    // prost's Message derive already implements Debug.
    prost_build::Config::new().compile_protos(&["proto/kestrel.proto"], &["proto"])?;
    Ok(())
}
