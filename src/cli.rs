use crate::sniffer::{sniff_packets, PacketStats};

use std::thread;
use pnet::datalink;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::mpsc;

pub struct Cli {
    data: Vec<HashMap<IpAddr, PacketStats>>,
}

impl Cli {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }

    fn start_sniffing(&mut self) {
        let interfaces = datalink::interfaces();
        let (tx, rx) = mpsc::channel();
        let mut handles = vec![];

        for interface in interfaces {
            let tx = tx.clone();
            let handle = thread::spawn(move || sniff_packets(interface, tx));
            handles.push(handle);
        }

        drop(tx);

        while let Ok((interface_name, stats)) = rx.recv() {
            println!("Received stats for interface: {}", interface_name);
            self.update_data(interface_name, stats);
            println!("data: {:#?}", self.data);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }


    // this is dumb, update stats, not add :)
    fn update_data(&mut self, interface_name: String, stats: HashMap<IpAddr, PacketStats>) {
        self.data.push(stats);
    }

    pub fn run(&mut self) {
        self.start_sniffing();
    }
}

/*
initialization: 
read json -> update the hasmap
    for this each thread will find its part of the hashmap and parse only needed part
    so each thread will have its own hashmap dedicated to only one interface

cli:
    start -> run sniff packets and update each hashmap
    stop -> stops sniffing and updates the json

*/