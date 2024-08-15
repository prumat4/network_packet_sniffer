use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

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
    println!("Parsed packet: {:?}", ethernet_packet.from_packet());
    println!("---");
}

pub fn sniff_packets(interface: NetworkInterface) {
    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type for interface: {}", interface.name),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    println!("Started packet sniffing on: {}", interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                                let source_ip = IpAddr::V4(ipv4_packet.get_source());
                                let dest_ip = IpAddr::V4(ipv4_packet.get_destination());
                                println!(
                                    "IPv4 packet: {} => {}",
                                    source_ip, dest_ip
                                );
                            }
                            print_packet_info(&interface, ethernet_packet);
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                                let source_ip = IpAddr::V6(ipv6_packet.get_source());
                                let dest_ip = IpAddr::V6(ipv6_packet.get_destination());
                                println!(
                                    "IPv6 packet: {} => {}",
                                    source_ip, dest_ip
                                );
                            }
                            print_packet_info(&interface, ethernet_packet);
                        }
                        _ => {
                            println!(
                                "Unhandled packet type: {:?}",
                                ethernet_packet.get_ethertype()
                            );
                        }
                    }
                    println!("---");
                }
            }
            Err(e) => panic!("Error reading packet: {}", e),
        }
    }
}