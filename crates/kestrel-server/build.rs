fn main() {
    println!("cargo:rustc-check-cfg=cfg(kestrel_ui_assets)");
    println!("cargo:rerun-if-changed=../../web/build");
    if std::path::Path::new("../../web/build/index.html").is_file() {
        println!("cargo:rustc-cfg=kestrel_ui_assets");
    }
}
