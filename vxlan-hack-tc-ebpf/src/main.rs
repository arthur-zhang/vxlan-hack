#![no_std]
#![no_main]

use core::f32::consts::E;
use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::{BPF_F_RECOMPUTE_CSUM, TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_l4_csum_replace;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
use memoffset::offset_of;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::udp::UdpHdr;

pub const VXLAN_PORT: u16 = 8472;

const UDP_CSUM_OFF: u32 = (EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check)) as u32;
const PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
const FAKE_VXLAN_FLAG_BYTE: u8 = 0x88;
const REAL_VXLAN_FLAG_BYTE: u8 = 0x08;

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let _ = try_tc_egress(ctx);
    TC_ACT_PIPE
}
#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let _ = try_tc_ingress(ctx);
    TC_ACT_PIPE
}


fn get_vxlan_flag(ctx: &TcContext) -> Result<u8, ()> {
    if ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 1 > ctx.data_end() {
        return Err(());
    }

    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    let eth_type = eth_hdr.ether_type;

    if eth_type != EtherType::Ipv4 {
        return Err(());
    }

    // load the IPv4 header
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    if ipv4hdr.proto != IpProto::Udp {
        return Err(());
    }
    // load the UDP header
    let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

    // check if the destination port is VXLAN
    let dst_port = u16::from_be(udp_hdr.dest);
    if dst_port != VXLAN_PORT {
        return Err(());
    }
    // load vxlan flag byte
    let first_byte: u8 = ctx.load(PAYLOAD_OFFSET).map_err(|_| ())?;
    Ok(first_byte)
}


fn try_tc_egress(ctx: TcContext) -> Result<(), ()> {
    let first_byte: u8 = get_vxlan_flag(&ctx)?;

    info!(&ctx, "try_tc_egress >>> VXLAN packet, first_byte: {}", first_byte);

    if first_byte != REAL_VXLAN_FLAG_BYTE {
        return Ok(());
    }
    let target_val = FAKE_VXLAN_FLAG_BYTE;
    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            PAYLOAD_OFFSET as u32,
            &target_val as *const _ as *const _,
            1,
            BPF_F_RECOMPUTE_CSUM as u64,
        )
    };
    if ret != 0 {
        info!(&ctx, "try_tc_egress bpf_skb_store_bytes failed");
    }

    let ret = unsafe {
        bpf_l4_csum_replace(ctx.skb.skb, UDP_CSUM_OFF, REAL_VXLAN_FLAG_BYTE as u64, FAKE_VXLAN_FLAG_BYTE as u64, 2)
    };
    if ret != 0 {
        info!(&ctx, "try_tc_egress bpf_l4_csum_replace failed");
    }

    Ok(())
}

fn try_tc_ingress(mut ctx: TcContext) -> Result<(), ()> {
    let first_byte: u8 = get_vxlan_flag(&ctx)?;

    info!(&ctx, "try_tc_ingress >>> VXLAN packet, first_byte: {}", first_byte);

    if first_byte != FAKE_VXLAN_FLAG_BYTE {
        return Ok(());
    }

    let target_val = REAL_VXLAN_FLAG_BYTE;

    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            PAYLOAD_OFFSET as u32,
            &target_val as *const _ as *const _,
            1,
            0,
        )
    };
    if ret != 0 {
        info!(&ctx, "try_tc_ingress bpf_skb_store_bytes failed");
        return Err(());
    }
    info!(&ctx, "try_tc_ingress bpf_skb_store_bytes success");
    let ret = unsafe {
        bpf_l4_csum_replace(ctx.skb.skb, UDP_CSUM_OFF, FAKE_VXLAN_FLAG_BYTE as u64, REAL_VXLAN_FLAG_BYTE as u64, 2)
    };
    if ret != 0 {
        info!(&ctx, "try_tc_ingress bpf_l4_csum_replace failed");
    }

    Ok(())
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
