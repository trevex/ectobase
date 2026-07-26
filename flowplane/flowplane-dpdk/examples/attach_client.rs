//! Minimal gRPC client for the full-serve af_xdp e2e harness (`hack/dpdk/serve-e2e.sh`).
//!
//! Connects to a running `flowplane-dpdk serve` DataplaneNode over `--addr` and issues the control
//! RPCs the e2e scenario needs, in one of a few tiny command modes so the shell harness can program
//! the datapath step by step and read back the assigned guest ifname / underlay from AttachInterface.
//!
//! This is a TEST HARNESS artifact only — it drives the exact `flowplane_node::pb` request types the
//! server handles (routes/NAT/firewall/attach), reusing the known-good addressing from
//! `nfkit/tests/guest_tx_nat_return_handoff.rs` so the injected frames + expected encap match a
//! proven scenario.
//!
//! Commands (first positional arg after `--addr <ADDR>`):
//!   route   --vni V --prefix CIDR --nexthop UL6 [--external]
//!   nat     --vni V --source IP4 --nat-ip IP4 --port-min P --port-max P
//!   fw      --iface ID --rule-id ID --src-cidr C --dst-cidr C --proto N \
//!           --dport-min P --dport-max P [--allow] [--egress]
//!   attach  --iface ID --netns PATH --vni V --ip IP [--ip IP2]
//!
//! On `attach` success it prints two machine-readable lines the harness greps:
//!   ATTACH_IFNAME=<guest ifname in the netns>
//!   ATTACH_UNDERLAY=<allocated underlay /128>   (the outer dst the NAT-return must target)

use flowplane_node::pb;
use pb::dataplane_node_client::DataplaneNodeClient;

/// Tiny hand-rolled flag reader (avoids pulling clap into the example): returns the value following
/// `--name`, or `None`.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
/// Repeatable flag: all values following each `--name`.
fn flags(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}
fn present(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
fn req<T>(o: Option<T>, what: &str) -> T {
    o.unwrap_or_else(|| panic!("missing required flag {what}"))
}
fn u32flag(args: &[String], name: &str) -> Option<u32> {
    flag(args, name).map(|s| s.parse().unwrap_or_else(|_| panic!("bad u32 {name}={s}")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let addr = flag(&args, "--addr").unwrap_or_else(|| "http://127.0.0.1:1337".to_string());
    let addr = if addr.starts_with("http") {
        addr
    } else {
        format!("http://{addr}")
    };
    // The command is the first positional arg that is not a flag/flag-value. Simplest: it is argv[1].
    let cmd = args.get(1).cloned().unwrap_or_default();

    let mut client = DataplaneNodeClient::connect(addr).await?;

    match cmd.as_str() {
        "route" => {
            client
                .add_route(pb::AddRouteRequest {
                    vni: req(u32flag(&args, "--vni"), "--vni"),
                    prefix: req(flag(&args, "--prefix"), "--prefix"),
                    nexthop_underlay: flag(&args, "--nexthop").unwrap_or_default(),
                    external: present(&args, "--external"),
                })
                .await?;
            println!("ROUTE_OK");
        }
        "nat" => {
            client
                .add_nat_source(pb::AddNatSourceRequest {
                    vni: req(u32flag(&args, "--vni"), "--vni"),
                    source_ip: req(flag(&args, "--source"), "--source"),
                    nat_ip: req(flag(&args, "--nat-ip"), "--nat-ip"),
                    port_min: req(u32flag(&args, "--port-min"), "--port-min"),
                    port_max: req(u32flag(&args, "--port-max"), "--port-max"),
                })
                .await?;
            println!("NAT_OK");
        }
        "fw" => {
            client
                .add_fw_rule(pb::AddFwRuleRequest {
                    interface_id: req(flag(&args, "--iface"), "--iface"),
                    rule_id: req(flag(&args, "--rule-id"), "--rule-id"),
                    src_cidr: flag(&args, "--src-cidr").unwrap_or_default(),
                    dst_cidr: flag(&args, "--dst-cidr").unwrap_or_default(),
                    proto: u32flag(&args, "--proto").unwrap_or(0),
                    dst_port_min: u32flag(&args, "--dport-min").unwrap_or(0),
                    dst_port_max: u32flag(&args, "--dport-max").unwrap_or(0),
                    allow: present(&args, "--allow"),
                    egress: present(&args, "--egress"),
                })
                .await?;
            println!("FW_OK");
        }
        "attach" => {
            let resp = client
                .attach_interface(pb::AttachInterfaceRequest {
                    interface_id: req(flag(&args, "--iface"), "--iface"),
                    netns_path: req(flag(&args, "--netns"), "--netns"),
                    vni: req(u32flag(&args, "--vni"), "--vni"),
                    mac: flag(&args, "--mac").unwrap_or_default(),
                    requested_ips: flags(&args, "--ip"),
                    device_type: String::new(),
                    tap_name: String::new(),
                })
                .await?
                .into_inner();
            // Machine-readable lines the harness greps for the assigned ifname / underlay + the MAC.
            println!("ATTACH_IFNAME={}", resp.ifname);
            println!("ATTACH_IPS={}", resp.ips.join(","));
            println!("ATTACH_MAC={}", resp.mac);
            println!("ATTACH_GATEWAY={}", resp.gateway);
            println!("ATTACH_UNDERLAY={}", resp.underlay_route);
        }
        other => {
            eprintln!("unknown command {other:?}; expected route|nat|fw|attach");
            std::process::exit(2);
        }
    }
    Ok(())
}
