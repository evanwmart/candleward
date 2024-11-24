use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

/// Starts the packet filtering engine.
/// If `interface_name` is provided, it tries to use the specified interface. Otherwise, it falls back to the first active interface.
pub fn start_packet_filtering(interface_name: Option<&str>) {
    // Get a list of all available network interfaces.
    let interfaces = datalink::interfaces();

    // Find the user-specified interface or the first active (non-loopback) interface.
    let interface = if let Some(name) = interface_name {
        interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .unwrap_or_else(|| {
                eprintln!("Specified network interface '{}' not found.", name);
                eprintln!("Available interfaces:");
                for iface in datalink::interfaces() {
                    eprintln!("- {}", iface.name);
                }
                std::process::exit(1);
            })
    } else {
        interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback())
            .expect("No suitable network interface found")
    };

    println!("Using interface: {}", interface.name);

    // Create a datalink channel for capturing packets on the selected interface.
    match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(_tx, mut rx)) => {
            println!("Packet filtering started. Press Ctrl+C to stop.");
            
            // Loop to capture and process packets.
            loop {
                match rx.next() {
                    Ok(packet) => {
                        // Parse the Ethernet frame
                        if let Some(ethernet) = EthernetPacket::new(packet) {
                            handle_packet(&ethernet);
                        }
                    }
                    Err(e) => eprintln!("Failed to read packet: {}", e),
                }
            }
        }
        Ok(_) => {
            eprintln!("Unexpected channel type: only Ethernet channels are supported.");
        }
        Err(e) => {
            eprintln!("Failed to create datalink channel: {}", e);
        }
    }
}

/// Handles incoming Ethernet packets.
fn handle_packet(packet: &EthernetPacket) {
    // Check if the packet contains an IPv4 payload.
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                println!(
                    "Captured IPv4 packet: {} -> {}",
                    ipv4_packet.get_source(),
                    ipv4_packet.get_destination()
                );
                // Add filtering logic here
            }
        }
        _ => {
            println!("Non-IPv4 packet captured");
        }
    }
}
