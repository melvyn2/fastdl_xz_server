use std::env;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::exit;

use serde::Deserialize;

use rouille::{Response, ResponseBody};

use xz2::read::XzDecoder;

#[derive(Deserialize, Debug)]
struct LoadedConfig {
    // TF2 is IPv4 only :/
    ip: Option<Ipv4Addr>,
    port: u16,
    paths: Vec<PathBuf>,
    allowed_hosts: Option<Vec<String>>,
}
struct RunConfig {
    socket: (Ipv4Addr, u16),
    paths: Vec<PathBuf>,
    allowed_hosts: Vec<String>,
}

impl Default for LoadedConfig {
    fn default() -> Self {
        Self {
            ip: None,
            port: 27999,
            paths: Vec::from([PathBuf::from("/var/www/maps")]),
            allowed_hosts: Some(Vec::from(["localhost".to_string()])),
        }
    }
}

fn print_help() {
    println!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    println!("Usage:");
    println!(
        "\t{} [PATH]",
        env::args()
            .nth(0)
            .unwrap_or(env!("CARGO_PKG_NAME").to_string())
    );
    println!("Where [PATH] is an optional path to the TOML-format config file");
}

fn process_whitelist(hosts: Option<Vec<String>>) -> Vec<String> {
    if hosts.is_none() {
        return vec![];
    }

    hosts
        .unwrap()
        .iter()
        .map(|input| "hl2://".to_string() + input)
        .collect::<Vec<String>>()
}

// Technically vulnerable:
// Can be bypassed by having the same start of hostname
// Should be infeasible with ips,
// but someone could try to use 'example.com.ua' to impersonate server 'example.com'
// So unlikely that I left it :)
fn filter_hosts(host: &str, allowed_hosts: &Vec<String>) -> bool {
    // If empty just skip
    allowed_hosts.len() == 0
        || allowed_hosts
            .iter()
            .map(|allowed| host.starts_with(allowed.as_str()))
            .fold(false, |res, new| res || new)
}

fn main() {
    if env::args()
        .find(|arg| (arg == "-h") || (arg == "--help"))
        .is_some()
    {
        print_help();
        exit(0)
    }

    let loaded_config = {
        let passed_path_str = env::args().nth(1).unwrap_or("/etc/fdl.toml".to_string());
        let passed_path = PathBuf::from(passed_path_str);

        if passed_path.exists() {
            let config_file = passed_path.canonicalize().unwrap();
            println!("Using config file {}", config_file.to_str().unwrap());

            let config_str = std::fs::read_to_string(config_file).unwrap();
            toml::from_str(config_str.as_str()).unwrap_or_else(|e| {
                eprintln!("Config file could not be parsed: {}", e);
                eprintln!("Using defaults");
                LoadedConfig::default()
            })
        } else {
            println!(
                "{} does not exist, using defaults",
                passed_path.to_str().unwrap()
            );
            LoadedConfig::default()
        }
    };
    println!("{:?}", loaded_config);

    let runconfig = RunConfig {
        socket: (
            loaded_config.ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
            loaded_config.port,
        ),
        paths: loaded_config.paths,
        allowed_hosts: process_whitelist(loaded_config.allowed_hosts),
    };

    rouille::start_server(runconfig.socket, move |request| {
        rouille::log(&request, std::io::stdout(), || {
            if !filter_hosts(
                request.header("referer").unwrap_or_default(),
                &runconfig.allowed_hosts,
            ) {
                return Response {
                    status_code: 403,
                    headers: vec![],
                    data: ResponseBody::empty(),
                    upgrade: None,
                };
            };
            if request.method() != "GET" {
                return Response {
                    status_code: 405,
                    headers: vec![],
                    data: ResponseBody::empty(),
                    upgrade: None,
                };
            };
            if !request.url().starts_with("/maps/") {
                return Response {
                    status_code: 404,
                    headers: vec![],
                    data: ResponseBody::empty(),
                    upgrade: None,
                };
            };

            let xz_name = request.url().drain(6..).collect::<String>() + ".xz";
            let path = (&runconfig.paths)
                .iter()
                .map(|path| path.join(&xz_name))
                .find(|path| path.is_file());

            if !path.is_some() {
                return Response {
                    status_code: 404,
                    headers: vec![],
                    data: ResponseBody::empty(),
                    upgrade: None,
                };
            };

            Response {
                status_code: 200,
                headers: vec![],
                data: ResponseBody::from_reader(XzDecoder::new(File::open(path.unwrap()).unwrap())),
                upgrade: None,
            }
        })
    });
}
