
extern crate pnet;
extern crate ipnetwork;

use std::env;
use std::net::{IpAddr, Ipv4Addr, AddrParseError};

use ipnetwork::{IpNetwork};
use pnet::datalink::{self, Channel, NetworkInterface, MacAddr, ParseMacAddrErr};

use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation};

fn send_arp_packet(
    interface: NetworkInterface,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    arp_operation: ArpOperation) {

    let(mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(arp_operation);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(ethernet_packet.packet(), Some(interface));
}


fn main() {
    println!("Starting...");
    let interface_name = env::args().nth(1).unwrap();
    println!("Interface name is {}", interface_name);
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    println!("Interface: {}", interface);

    let interface_clone = interface.clone();

    let source_mac = interface.mac_address();
    let source_network = interface.ips.first().unwrap();
    let source_ip = source_network.ip();
    let arp_operation = ArpOperations::Request;
    let target_mac = MacAddr::new(255,255,255,255,255,255);

    match source_network {
        &IpNetwork::V4(source_networkv4) => {
            for target_ipv4 in source_networkv4.iter() {
                match source_ip {
                    IpAddr::V4(source_ipv4) => {
                        send_arp_packet(interface_clone.clone(), source_ipv4, source_mac, target_ipv4, target_mac, arp_operation);
                    },
                    _ => {}
                }

            }
        },
        _ => {}
    }


}
