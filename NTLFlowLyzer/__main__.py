#!/usr/bin/env python3

import argparse
import glob
import json
import os

from NTLFlowLyzer.config_loader import ConfigLoader
from .network_flow_analyzer import NTLFlowLyzer

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='ntlflowlyzer', description='Network Traffic Flow Analyzer')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    parser.add_argument('-b', '--batch-mode', action='store_true',
                        help='Analyze all the files in the given directory. The default is False.')
    parser.add_argument('-cb', '--continues-batch-mode', action='store_true',
                        help='Continues batch mode. Analyze files in the given directory continuously.'
                            ' Default is False.')
    parser.add_argument('-f', '--pcap-file', action='store',
                        help='Path to specific PCAP file to analyze.')
    parser.add_argument('--csv', action='store',
                        help='Path for output CSV file. (default = ntlflowlyer-output.csv)', default='ntlflowlyer-output.csv')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output.')
    return parser


def find_pcap_files(directory):
    file_pattern = directory + '/*'
    pcap_files = glob.glob(file_pattern)
    return pcap_files


def main():
    parsed_arguments = args_parser().parse_args()
    if len(vars(parsed_arguments)) == 0:
        args_parser().print_help()
        return

    if not parsed_arguments.batch_mode:
        config = ConfigLoader(parsed_arguments.config_file, parsed_arguments.pcap_file, parsed_arguments.csv)
        # print all values in config
        print(">> Configurations:")
        for key, value in vars(config).items():
            print(f"{key}: {value}")
        network_flow_analyzer = NTLFlowLyzer(config, parsed_arguments.online_capturing, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()
        return

    print(">> Batch mode is on.")
    config = ConfigLoader(parsed_arguments.config_file)
    batch_address = config.batch_address
    batch_address_output = config.batch_address_output
    pcap_files = find_pcap_files(batch_address)
    print(f">> {len(pcap_files)} number of files detected in the batch directory.")
    for file in pcap_files:
        print(100*"#")
        output_file_name = file.split('/')[-1]
        config.pcap_file_address = file
        config.output_file_address = f"{batch_address_output}/{output_file_name}.csv"
        network_flow_analyzer = NTLFlowLyzer(config, parsed_arguments.online_capturing, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()


if __name__ == "__main__":
    main()
