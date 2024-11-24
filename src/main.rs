mod packet_filter;

use clap::Parser;

/// Command-line arguments for the Candleward firewall.
#[derive(Parser)]
struct Args {
    /// Name of the network interface to monitor.
    #[arg(short, long, default_value = "")]
    interface: String,
}

fn main() {
    let args = Args::parse();

    println!("Starting Candleward Packet Filtering Engine...");

    // Pass the interface argument to the packet filter.
    packet_filter::start_packet_filtering(if args.interface.is_empty() {
        None
    } else {
        Some(args.interface.as_str())
    });
}
