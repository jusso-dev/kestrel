fn main() {
    if let Err(err) = kestrel_agent::run() {
        eprintln!("kestrel-agent: {err}");
        std::process::exit(1);
    }
}
