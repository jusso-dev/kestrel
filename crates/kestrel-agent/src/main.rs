fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--configure") {
        match kestrel_agent::bootstrap::from_stdin(&args) {
            Ok(path) => println!("Agent configured at {}", path.display()),
            Err(err) => {
                eprintln!("kestrel-agent: {err}");
                std::process::exit(1);
            }
        }
        return;
    }
    if std::env::args().any(|arg| arg == "--service") {
        if let Err(err) = kestrel_agent::service::service_entry() {
            eprintln!("kestrel-agent service: {err}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(err) = kestrel_agent::run() {
        eprintln!("kestrel-agent: {err}");
        std::process::exit(1);
    }
}
