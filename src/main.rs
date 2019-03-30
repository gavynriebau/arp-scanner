
extern crate pnet;
extern crate ipnetwork;
extern crate clap;

#[macro_use]
extern crate prettytable;

use clap::{Arg, App, ArgMatches};

use prettytable::Table;
use prettytable::format;

use std::time::Duration;
use std::thread;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::{self, Sender, Receiver};
use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::{IpNetwork};
use pnet::datalink::{self, Channel, NetworkInterface, MacAddr};

use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket};

const BANNER : &str = r#"
  ____  ____   ____        _____   __   ____  ____   ____     ___  ____  
 /    ||    \ |    \      / ___/  /  ] /    ||    \ |    \   /  _]|    \ 
|  o  ||  D  )|  o  )    (   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
|     ||    / |   _/      \__  |/  /  |     ||  |  ||  |  ||    _]|    / 
|  _  ||    \ |  |        /  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \ 
|  |  ||  .  \|  |        \    \     ||  |  ||  |  ||  |  ||     ||  .  \
|__|__||__|\_||__|         \___|\____||__|__||__|__||__|__||_____||__|\_|

"#;

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
        Err(e) => panic!("Error happened {}", e)
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

fn recv_arp_packets(interface: NetworkInterface, tx: Sender<(Ipv4Addr, MacAddr)>) {

    thread::spawn(move || {
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
                        let result: (Ipv4Addr, MacAddr) = (arp_packet.get_sender_proto_addr(), arp_packet.get_sender_hw_addr());
                        tx.send(result).unwrap();
                    }
                },
                Err(e) => panic!("An error occurred while reading packet: {}", e)
            }
        }
    });
}

fn main() {

	let matches = App::new(BANNER)
		.author("Gavyn Riebau <gavyn.riebau@gmail.com>")
		.about("\nRuns an ARP scan to discover all hosts in the network")
		.arg(Arg::with_name("interface")
			.short("i")
			.long("interface")
			.value_name("INTERFACE")
			.help("The interface on which the scan will be performed")
			.required_unless_one(&["list", "interface_index"])
			.conflicts_with("interface_index")
		)
		.arg(Arg::with_name("interface_index")
			.short("x")
			.long("index")
			.value_name("INTERFACE_INDEX")
			.help("The index of the interface rather than the interface name.")
			.required_unless_one(&["list", "interface"])
			.conflicts_with("interface")
		)
		.arg(Arg::with_name("list")
			.short("l")
			.long("list")
			.help("List available interfaces including their index")
			.conflicts_with("interface")
		)
        .arg(Arg::with_name("output")
             .short("o")
             .long("out")
             .value_name("FILE")
             .help("Write results to a file in CSV format")
         )
		.get_matches();

	println!("{}", BANNER);

	if matches.is_present("list") {
		println!("Listing interfaces:\n");
		let interfaces = datalink::interfaces();
		for interface in interfaces.iter() {
			println!("{}\n", interface);
		}
		std::process::exit(0);
	}

    let interface_match = |iface: &NetworkInterface| {
		if matches.is_present("interface") {
			return &iface.name == matches.value_of("interface").unwrap();
		} else {
			let index_str = matches.value_of("interface_index").unwrap();
			let index : u32 = index_str.parse().unwrap();

			return iface.index == index;
		}
	};

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_match)
        .next()
        .unwrap();

	if interface.is_loopback() {
		println!("Aborting because chosen interface is a loopback interface.\nChoose a non-loopback interface.\n");
		std::process::exit(1);
	}

	if interface.ips.is_empty() {
		println!("Aborting because chosen interface doesn't have a network address.\n");
		std::process::exit(1);
	}

    println!("Using interface: {}\n", interface);

    let source_mac = interface.mac_address();
    let source_network = interface.ips.iter().find(|x| x.is_ipv4()).unwrap();
    let source_ip = source_network.ip();
    let arp_operation = ArpOperations::Request;
    let target_mac = MacAddr::new(255,255,255,255,255,255);

    // Channel for ARP replies.
    let (tx, rx): (Sender<(Ipv4Addr, MacAddr)>, Receiver<(Ipv4Addr, MacAddr)>) = mpsc::channel();

    recv_arp_packets(interface.clone(), tx);

    println!("[X] Sending ARP requests...");

    match source_network {
        &IpNetwork::V4(source_networkv4) => {
            for target_ipv4 in source_networkv4.iter() {
                match source_ip {
                    IpAddr::V4(source_ipv4) => {
                        send_arp_packet(interface.clone(), source_ipv4, source_mac, target_ipv4, target_mac, arp_operation);
                    },
                    e => panic!("Error while parsing to IPv4 address: {}", e)
                }

            }
        },
        e => panic!("Error while attempting to get network for interface: {}", e)
    }
    println!("[X] Collecting results...");
    thread::sleep(Duration::from_secs(2));
    println!();

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["host", "mac"]);

    loop {
        match rx.try_recv() {
            Ok((ipv4_addr, mac_addr)) => {
                table.add_row(row![ipv4_addr, mac_addr]);
            },
            Err(_) => break
        }
    }

	if table.len() > 0 {
		table.printstd();

        if matches.is_present("output") {
            let out_file = get_out_file(&matches);
            let _ = table.to_csv(out_file).expect("Failed to write results to CSV.");
        }

	} else {
		println!("No hosts found...");

        if matches.is_present("output") {
            let mut out_file = get_out_file(&matches);
            let _ = out_file.write_all(b"No hosts found...").unwrap();
        }
	}

}

fn get_out_file(matches: &ArgMatches) -> File {
    File::create(matches.value_of("output").unwrap()).expect("Failed to open out file.")
}

