fn main() {
    if let Err(err) = kestrel_server::run() {
        eprintln!("kestrel-server: {err}");
        std::process::exit(1);
    }
}
