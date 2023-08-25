#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap,PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use sajjan_firewall_common::PacketLog;

#[map] //
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(32, 0);

#[map] //
static EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::with_max_entries(256, 0);

#[xdp]
pub fn sajjan_firewall(ctx: XdpContext) -> u32 {
    match try_sajjan_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_sajjan_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    //

    let action = if block_ip(source) || block_ip(destination) {
        let log_entry = PacketLog {
            ipv4_address_dst: destination,
            ipv4_address_src:source
        };
        EVENTS.output(&ctx, &log_entry, 0);
        xdp_action::XDP_PASS
        // xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    //info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
