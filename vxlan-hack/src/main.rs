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
    std::env::set_var("RUST_LOG", "debug");
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

    println!("loading eBPF program {}", concat!(env!("OUT_DIR"), "/vxlan-hack-tc-ebpf" ));

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vxlan-hack"
    )))?;


    let Opt { iface } = opt;

    if let Err(e) = BpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let detach_egress = tc::qdisc_detach_program(&iface, TcAttachType::Egress, "tc_egress");
    let detach_ingress = tc::qdisc_detach_program(&iface, TcAttachType::Ingress, "tc_ingress");
    if detach_egress.is_err() || detach_ingress.is_err() {
        info!("failed to detach existing programs, egress error {:?}, {:?}", detach_egress, detach_ingress);
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
    println!("Exiting...");

    Ok(())
}
