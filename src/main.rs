
extern crate pnet;
extern crate ipnetwork;

use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, AddrParseError};

use ipnetwork::{IpNetwork};
use pnet::datalink::{self, Channel, NetworkInterface, MacAddr, ParseMacAddrErr};

use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket};


fn print_arp_packet(packet: &ArpPacket) {
    println!("[{}]\t\t{}", packet.get_sender_proto_addr(), packet.get_sender_hw_addr());
}

fn send_arp_packet(
    interface: NetworkInterface,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    arp_operation: ArpOperation) {

    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
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

fn recv_arp_packets(interface: NetworkInterface) {

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e)
    };

    loop {
        match rx.next() {
            Ok(data) => {
                let ethernet_packet = EthernetPacket::new(data).unwrap();
                let ethernet_payload = ethernet_packet.payload();
                let arp_packet = ArpPacket::new(ethernet_payload).unwrap();
                let arp_reply_op = ArpOperation::new(2_u16);

                if arp_packet.get_operation() == arp_reply_op {
                    print_arp_packet(&arp_packet);
                }
                //println!("Received packet: {:?}", packet);
            },
            Err(e) => panic!("An error occurred while reading packet: {}", e)
        }
    }
}


fn main() {
    println!("Starting...\n");

    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    println!("Using interface: {}\n", interface);

    let source_mac = interface.mac_address();
    let source_network = interface.ips.first().unwrap();
    let source_ip = source_network.ip();
    let arp_operation = ArpOperations::Request;
    let target_mac = MacAddr::new(255,255,255,255,255,255);

    println!("Sending ARP requests");
    match source_network {
        &IpNetwork::V4(source_networkv4) => {
            for target_ipv4 in source_networkv4.iter() {
                match source_ip {
                    IpAddr::V4(source_ipv4) => {
                        send_arp_packet(interface.clone(), source_ipv4, source_mac, target_ipv4, target_mac, arp_operation);
                    },
                    _ => {}
                }

            }
        },
        _ => {}
    }

    println!("Receiving ARP responses");
    recv_arp_packets(interface.clone());
}
