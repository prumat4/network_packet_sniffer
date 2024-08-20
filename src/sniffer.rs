use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PacketStats {
    pub count: u64,
    pub size: u64,
}

fn print_packet_info(interface: &NetworkInterface, ethernet_packet: EthernetPacket) {
    println!(
        "Packet on {}: {} => {} (Ethertype: {})",
        interface.name,
        ethernet_packet.get_source(),
        ethernet_packet.get_destination(),
        ethernet_packet.get_ethertype()
    );
    println!("Packet data: {:?}", ethernet_packet.packet());
    println!("Payload: {:?}", ethernet_packet.payload());
    println!("--------------------------------------------------------------------------------------");
}

fn print_network_stats(interface_name: &str, stats: &HashMap<IpAddr, PacketStats>) {
    println!("Interface: {}", interface_name);
    println!("{:<30} {:<30} {:<30}", "IP", "Packets", "Total Size (bytes)");
    println!("--------------------------------------------------------------------------------------");
    for (ip, stat) in stats {
        println!("{:<30} {:<30} {:<30}", ip, stat.count, stat.size);
    }
    println!("--------------------------------------------------------------------------------------");
}

pub fn sniff_packets(interface: NetworkInterface, tx: mpsc::Sender<(String, HashMap<IpAddr, PacketStats>)>) {
    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type for interface: {}", interface.name),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let mut network_stats: HashMap<IpAddr, PacketStats> = HashMap::new();

    println!("Started packet sniffing on: {}", interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let mut updated = false;

                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                                let source_ip = IpAddr::V4(ipv4_packet.get_source());
                                let packet_size = ipv4_packet.packet().len() as u64;
                                update_stats(&mut network_stats, source_ip, packet_size);
                                updated = true;
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                                let source_ip = IpAddr::V6(ipv6_packet.get_source());
                                let packet_size = ipv6_packet.packet().len() as u64;
                                update_stats(&mut network_stats, source_ip, packet_size);
                                updated = true;
                            }
                        }
                        _ => {
                            println!("Unhandled packet type: {:?}", ethernet_packet.get_ethertype());
                        }
                    }

                    if updated {
                        if tx.send((interface.name.clone(), network_stats.clone())).is_err() {
                            println!("Failed to send packet stats");
                        }
                    }
                }
            }
            Err(e) => panic!("Error reading packet: {}", e),
        }
    }
}


fn update_stats(stats: &mut HashMap<IpAddr, PacketStats>, ip: IpAddr, packet_size: u64) {
    let entry = stats.entry(ip).or_insert(PacketStats { count: 0, size: 0 });
    entry.count += 1;
    entry.size += packet_size;
}
