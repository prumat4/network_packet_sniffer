/*
next steps:
1. make the stats to save between reboots

2. cli in separate thread :
    add start one/all command
    add stop one/all commnd
    show ip count
    show ip size
    show stats for interface 
    --help

*/
use crate::sniffer::{sniff_packets, PacketStats};
use std::thread;
use pnet::datalink;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::fs::File;
use serde_json;
use std::env;

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
            packet_threshold: 500,
            packets_since_last_save: 0,
        }
    }

    fn load_stats(&mut self) {
        let mut json_dir = env::current_dir().expect("Failed to get current directory");
        json_dir.push("jsons");
    
        if !json_dir.is_dir() {
            println!("jsons directory does not exist, creating it");
            std::fs::create_dir_all(&json_dir).expect("Failed to create jsons directory");
        }
    
        let mut general_data_path = json_dir.clone();
        general_data_path.push("general_data.json");
        
        if general_data_path.exists() {
            let file = File::open(&general_data_path).expect("Failed to open general data file");
            let data: HashMap<String, HashMap<IpAddr, PacketStats>> =
                serde_json::from_reader(file).expect("Failed to parse general data file");
            
            self.data = data;
            println!("Loaded general data from {}", general_data_path.display());
        } else {
            println!("No general data file found, starting with empty data");
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
    
        while let Ok((interface_name, ip, packet_size)) = rx.recv() {
            self.update_data(interface_name, ip, packet_size);
    
            self.packets_since_last_save += 1;
    
            if self.last_save_time.elapsed() >= Duration::new(1, 0) 
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

    fn update_data(&mut self, interface_name: String, ip: IpAddr, packet_size: u64) {
        let entry = self.data.entry(interface_name.clone()).or_insert_with(HashMap::new);
        let interface_entry = entry.entry(ip).or_insert(PacketStats { count: 0, size: 0 });
    
        interface_entry.count += 1;
        interface_entry.size += packet_size;
    }

    fn save_stats(&self) {
        let mut json_dir = env::current_dir().expect("Failed to get current directory");
        json_dir.push("jsons");
    
        std::fs::create_dir_all(&json_dir).expect("Failed to create jsons directory");
    
        for (interface_name, stats) in &self.data {
            let mut file_path = json_dir.clone();
            file_path.push(format!("{}.json", interface_name));
            let file = File::create(&file_path).expect("Failed to create file");
    
            if let Err(e) = serde_json::to_writer_pretty(file, stats) {
                println!("Failed to save stats for interface {}: {}", interface_name, e);
            } else {
                println!("Saved stats for interface {} to {}", interface_name, file_path.display());
            }
        }

        // do we even need general stats? 
        let mut general_data_path = json_dir.clone();
        general_data_path.push("general_data.json");
        let file = File::create(&general_data_path).expect("Failed to create file");
    
        if let Err(e) = serde_json::to_writer_pretty(file, &self.data) {
            println!("Failed to save general data: {}", e);
        } else {
            println!("Saved general data to {}", general_data_path.display());
        }
    }
    
    pub fn run(&mut self) {
        self.load_stats();
        self.start_sniffing();
    }
}
