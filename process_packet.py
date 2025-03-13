from scapy.all import IP, UDP, TCP, rdpcap
import pandas as pd
from datetime import datetime
from collections import deque
import logging
import asyncio


class PacketProcessor(object):
    """Class for gathering and storing packet information."""

    def __init__(self):
        self.__protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        self.__packet_data = deque()
        self.__start_time = datetime.now()
        self.__packet_count = 0

    def get_protocol_name(self, protocol_num: int) -> str:
        """Return the protocol name mapped to the protocol_num parameter or OTHER"""
        return self.__protocol_map.get(protocol_num, f"OTHER{protocol_num}")

    def get_packet_info(self, packet) -> dict:
        """Return a key:value pair containing inforamtion about the current packet being processed."""
        packet_info = {
            "timestamp": datetime.now(),
            "source": packet[IP].src,
            "destination": packet[IP].dst,
            "protocol": self.get_protocol_name(packet[IP].proto),
            "size": len(packet),
            "relative_time": (datetime.now() - self.__start_time).total_seconds()
        }

        if TCP in packet:
            packet_info.update({
                "sport": packet[TCP].sport,
                "dport": packet[TCP].dport,
                "flags": str(packet[TCP].flags)
            })
        elif UDP in packet:
            packet_info.update({
                "sport": packet[UDP].sport,
                "dport": packet[UDP].dport
            })

        return packet_info

    async def read_pcap_file(self, filename):
        """Asynchronously read packets from a pcap file."""
        loop = asyncio.get_running_loop()

        def read_file():
            return rdpcap(filename)
        packets = await loop.run_in_executor(None, read_file)
        return packets

    async def process_packets(self, filename, batch_size=5000) -> None:
        """Process current packet containing the IP header in batches."""
        try:
            packets = await self.read_pcap_file(filename)
            total_packets = len(packets)
            logging.info(f"Read {total_packets} packets from {filename}.")
            for i in range(0, total_packets, batch_size):
                batch = packets[i:i+batch_size]
                for packet in batch:
                    if IP in packet:
                        packet_info = self.get_packet_info(packet)
                        self.__packet_data.append(packet_info)
                        self.__packet_count += 1
                logging.info(
                    f"Processed {min(i+batch_size, total_packets)}/{total_packets} packets.")
                await asyncio.sleep(2)
            return self.__packet_count
        except Exception as e:
            logging.error(f"Error processing packet", e)
            return 0

    def get_dataframe(self) -> pd.DataFrame:
        """Return packet data as a pandas dataframe."""
        return pd.DataFrame(self.__packet_data)

    async def packet_stats(self):
        """Perform and return basic statistical analysis on packet data."""
        df = self.get_dataframe()
        if df.empty:
            return {"status": "No data available"}
        analysis = {
            "total_packets": len(df),
            "protocols": df['protocol'].value_counts().to_dict(),
            "top_ip_sources": df['source'].value_counts().head(5).to_dict(),
            "top_ip_destinations": df['destination'].value_counts().head(5).to_dict(),
            "avg_packet_size": df['size'].mean()
        }
        return analysis
