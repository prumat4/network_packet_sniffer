use crate::sniffer::{sniff_packets, PacketStats};
use std::thread;
use pnet::datalink;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::fs::File;
use serde_json;

pub struct Cli {
    data: HashMap<String, HashMap<IpAddr, PacketStats>>,
    last_save_time: Instant,
    packet_threshold: u64,
    packets_since_last_save: u64,
}

impl Cli {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            last_save_time: Instant::now(),
            packet_threshold: 100, // Save after processing 100 new packets
            packets_since_last_save: 0,
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
            self.update_data(interface_name, stats);
            println!("Current aggregated data: {:#?}", self.data);

            self.packets_since_last_save += 1;

            if self.last_save_time.elapsed() >= Duration::new(10, 0) 
                || self.packets_since_last_save >= self.packet_threshold {
                self.save_stats();
                self.last_save_time = Instant::now();
                self.packets_since_last_save = 0;
            }
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    fn update_data(&mut self, interface_name: String, stats: HashMap<IpAddr, PacketStats>) {
        let entry = self.data.entry(interface_name.clone()).or_insert_with(HashMap::new);

        for (ip, new_stats) in stats {
            let interface_entry = entry.entry(ip).or_insert(PacketStats { count: 0, size: 0 });
            interface_entry.count += new_stats.count;
            interface_entry.size += new_stats.size;
        }
    }

    fn save_stats(&self) {
        for (interface_name, stats) in &self.data {
            let file_path = format!("/home/logi/myself/programming/rust/side_projects/packet_sniffer/jsons/{}.json", interface_name);
            let file = File::create(file_path).expect("Failed to create file");
            if let Err(e) = serde_json::to_writer_pretty(file, stats) {
                println!("Failed to save stats for interface {}: {}", interface_name, e);
            }
        }
    
        // Save general data
        let file = File::create("/home/logi/myself/programming/rust/side_projects/packet_sniffer/jsons/general_data.json").expect("Failed to create file");
        if let Err(e) = serde_json::to_writer_pretty(file, &self.data) {
            println!("Failed to save general data: {}", e);
        }
    }
    
    pub fn run(&mut self) {
        self.start_sniffing();
    }
}
