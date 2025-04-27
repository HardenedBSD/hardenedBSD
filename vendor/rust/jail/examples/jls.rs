use cli_table::{print_stdout, Table, WithTitle};
use jail::RunningJail;

#[derive(Table)]
struct Jail {
    #[table(title = "JID")]
    jid: i32,

    #[table(title = "IP Address")]
    ips: String,

    #[table(title = "Hostname")]
    hostname: String,

    #[table(title = "Path")]
    path: String,
}

fn main() {
    pretty_env_logger::init();

    let mut jails = Vec::new();

    for j in RunningJail::all() {
        let ips: Vec<String> = j
            .ips()
            .unwrap()
            .iter()
            .map(|ip| format!("{}", ip))
            .collect();

        let jail = Jail {
            jid: j.jid,
            ips: ips.join("\n"),
            hostname: j.hostname().unwrap(),
            path: j.path().unwrap().to_str().unwrap().to_string(),
        };

        jails.push(jail);
    }

    print_stdout(jails.with_title()).unwrap();
}
