fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("admin") {
        kestrel_server::admin::admin_cli(args)
    } else {
        kestrel_server::run()
    };
    if let Err(err) = result {
        eprintln!("kestrel-server: {err}");
        std::process::exit(1);
    }
}
