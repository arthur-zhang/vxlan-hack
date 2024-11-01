use anyhow::Context as _;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya_log::BpfLogger;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use log::info;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let bpf_dir = std::env::var("BPF_DIR").unwrap_or("/tmp".to_string());
    let Opt { iface } = opt;

    let bpf_path = format!("{}/{}", bpf_dir, "vxlan-hack-tc-ebpf");
    println!("Loading eBPF program... {}", bpf_path);
    let bpf_data = std::fs::read(bpf_path).unwrap();;

    let mut ebpf = aya::Ebpf::load(&bpf_data[..])?;

    if let Err(e) = BpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier =
        ebpf.program_mut("tc_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Egress)?;

    info!("attached tc_egress");
    let ingress_program: &mut SchedClassifier =
        ebpf.program_mut("tc_ingress").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program.attach(&iface, TcAttachType::Ingress)?;


    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...{:?}", ebpf);

    Ok(())
}
