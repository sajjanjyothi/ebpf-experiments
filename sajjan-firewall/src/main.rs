use anyhow::{Context, Ok};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, maps, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use sajjan_firewall_common::PacketLog;
use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, Receiver, self};
use aya::maps::MapData;
use tokio::time::{sleep, Duration};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

fn clear(blocklist:& mut maps::HashMap<&mut MapData, u32, u32>){
    let v = blocklist.keys().collect::<Vec<Result<u32, aya::maps::MapError>>>();
    for k in v {
        blocklist.remove(&k.unwrap());
    }
}

async fn post_messages(rx: &Receiver<String>){
    for val in rx{
        let mut map = HashMap::new();
        map.insert("message",val);

        let client = reqwest::Client::new();
            let res = client.post("http://localhost:3000/api")
            .json(&map)
            .send().await;
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sajjan-firewall"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sajjan-firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("sajjan_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    task::spawn(async move{
        post_messages(&rx).await;
    });
    
    for cpu_id in online_cpus()? {
        let thread_tx = tx.clone();
        let mut buf = perf_array.open(cpu_id, None)?;
        task::spawn(async move{   
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned()};
                    let dst_addr = Ipv4Addr::from(data.ipv4_address_dst);
                    let src_addr = Ipv4Addr::from(data.ipv4_address_src);
                    info!("LOG: SRC {}  --> DST {}", src_addr,dst_addr);
                    thread_tx.send(format!("LOG: SRC {}  --> DST {}", src_addr,dst_addr)).unwrap();
                }
            }
        });
    }

    let mut blocklist: maps::HashMap<_, u32, u32> =
        maps::HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    //Get ip address from backend and log it
    loop {
        let resp = reqwest::get("http://localhost:3000/api")
            .await
            .unwrap()
            .json::<HashMap<String, String>>()
            .await
            .unwrap();
        println!("{:?}", resp);
        let ip_address = resp.get("ip_address").unwrap();
        println!("{}", ip_address);
        let bytes: Vec<&str> = ip_address.split(".").collect();
        let block_addr: u32 = Ipv4Addr::new(
            bytes[0].parse().unwrap(),
            bytes[1].parse().unwrap(),
            bytes[2].parse().unwrap(),
            bytes[3].parse().unwrap(),
        )
        .try_into()
        .unwrap();
        clear(&mut blocklist); //clear the block list for new ip collections
        if blocklist.get(&block_addr, 0).is_err() {
            //no key found
            blocklist.insert(block_addr, 0, 0).unwrap();
        }
        sleep(Duration::from_secs(5)).await;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
