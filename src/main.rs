use std::env;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::exit;

use rouille::{Request, Response, ResponseBody};

use serde::Deserialize;

use xz2::read::XzDecoder;

use log::{debug, error, info};

// Serde defaults can only use methods or functions, not predefined values
fn unspecified_ipv4() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}
fn default_port() -> u16 {
    27999
}

#[derive(Deserialize, Debug)]
struct Config {
    // Steam and Source Engine are IPv4 only
    #[serde(default = "unspecified_ipv4")]
    ip: Ipv4Addr,
    #[serde(default = "default_port")]
    port: u16,
    paths: Vec<PathBuf>,
    // hostname:port combinations to match in referrer
    #[cfg(feature = "filtering")]
    allowed_hosts: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip: unspecified_ipv4(),
            port: default_port(),
            paths: vec![PathBuf::from("/var/www/maps")],
            #[cfg(feature = "filtering")]
            allowed_hosts: vec!["localhost".to_string()],
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
            .next()
            .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string())
    );
    println!("Where [PATH] is an optional path to the TOML-format config file");
}

#[cfg(feature = "filtering")]
fn referrer_allowed(referrer: &str, allowed_hosts: &Vec<String>) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }

    referrer.starts_with("hl2://")
        && allowed_hosts
            .iter()
            .map(|host| host == referrer)
            .any(|matches| matches)
}

fn main() {
    if env::args().any(|arg| (&arg == "-h") || (&arg == "--help")) {
        print_help();
        exit(0)
    }

    // Log directly to systemd journal if available
    if systemd_journal_logger::connected_to_journal() {
        systemd_journal_logger::init_with_extra_fields(vec![(
            "VERSION",
            env!("CARGO_PKG_VERSION"),
        )])
        .unwrap();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    }

    let config = {
        let passed_path_str = env::args()
            .nth(1)
            .unwrap_or_else(|| "/etc/fdl.toml".to_string());
        let passed_path = PathBuf::from(passed_path_str);

        if passed_path.exists() {
            let config_file = passed_path.canonicalize().unwrap();
            debug!("Using config file {}", config_file.to_str().unwrap());

            let config_str = std::fs::read_to_string(config_file).unwrap();
            toml::from_str(config_str.as_str()).unwrap_or_else(|e| {
                error!("Config file could not be parsed: {}", e);
                error!("Using defaults");
                Config::default()
            })
        } else {
            error!(
                "{} does not exist, using defaults",
                passed_path.to_str().unwrap()
            );
            Config::default()
        }
    };
    info!("{:?}", config);

    rouille::start_server((config.ip, config.port), move |request| {
        let log_ok = |req: &Request, resp: &Response, elap: std::time::Duration| {
            info!(
                "{} {} - {} - {}ns",
                req.method(),
                req.raw_url(),
                resp.status_code,
                elap.as_nanos()
            );
        };
        let log_err = |req: &Request, elap: std::time::Duration| {
            error!(
                "Handler panicked: {} {} - {}ns",
                req.method(),
                req.raw_url(),
                elap.as_nanos()
            );
        };
        rouille::log_custom(request, log_ok, log_err, || {
            #[cfg(feature = "filtering")]
            {
                if !referrer_allowed(
                    request.header("referer").unwrap_or_default(),
                    &(config.allowed_hosts),
                ) {
                    return Response {
                        status_code: 403,
                        headers: vec![],
                        data: ResponseBody::from_string("FastDL restricted to whitelisted servers"),
                        upgrade: None,
                    };
                };
                if request.method() != "GET" {
                    return Response {
                        status_code: 405,
                        headers: vec![],
                        data: ResponseBody::from_string("GET only"),
                        upgrade: None,
                    };
                };
            }

            let xz_name = request.url() + ".xz";
            let path = config
                .paths
                .iter()
                .map(|path| {
                    path.clone()
                        .join(xz_name.strip_prefix('/').unwrap_or(&xz_name))
                })
                .find(|path| path.is_file());

            if path.is_none() {
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
