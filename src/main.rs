use std::thread;
use pnet::datalink;

use packet_sniffer::sniff_packets;

fn main() {
    let interfaces = datalink::interfaces();
    let mut handles = vec![];

    for interface in interfaces {
        let handle = thread::spawn(move || sniff_packets(interface));
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
