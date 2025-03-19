#!/usr/bin/env python3

import json
import multiprocessing

class ConfigLoader:
    def __init__(self, config_file_address: str = None, 
                 pcap_file_address: str = None,
                 output_file_address: str = None):
        self.batch_address: str = None
        self.vxlan_ip: str = None
        self.continues_batch_address: str = None
        self.continues_pcap_prefix: str = None
        self.batch_address_output: str = None
        self.number_of_continues_files: int = 0
        self.label: str = "Unknown"
        self.protocols: list = []
        self.interface_name: str = "eth0"
        self.max_flow_duration: int = 120000
        self.activity_timeout: int = 5000
        self.floating_point_unit: str = ".4f"
        self.features_ignore_list: list = []
        self.number_of_threads: int = multiprocessing.cpu_count()
        self.feature_extractor_min_flows: int = 4000
        self.writer_min_rows: int = 6000
        self.read_packets_count_value_log_info: int = 10000
        self.check_flows_ending_min_flows: int = 2000
        self.capturer_updating_flows_min_value: int = 2000
        self.max_rows_number: int = 900000
        self.config_file_address: str = config_file_address
        if config_file_address:
            self.read_config_file()
        self.pcap_file_address: str = pcap_file_address
        self.output_file_address: str = output_file_address
        
        if self.pcap_file_address is None and self.batch_address is None and self.continues_batch_address is None:
            raise Exception("Please specify the 'pcap_file_address' or 'batch_address' or 'continues_batch_address' in the config file.")

    def read_config_file(self):
        try:
            with open(self.config_file_address) as config_file:
                for key, value in json.loads(config_file.read()).items():
                    setattr(self, key, value)
        except Exception as error:
            print(f">> Error was detected while reading {self.config_file_address}: {str(error)}. ")
            exit(-1)
