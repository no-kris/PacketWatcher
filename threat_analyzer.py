import asyncio
import networkx as nx
import pandas as pd
import numpy as np
from scipy import stats

from process_packet import PacketProcessor

pcap_file = 'network_sim.pcap'


class ThreatAnalyzer(object):
    """Class ThreatAnalyzer uses graph theory to extract potential threat information from network traffic."""

    def __init__(self, dataframe: pd.DataFrame):
        self.__df = dataframe
        self.__ports_list = self.get_ports_list()
        self.__network_graph = nx.MultiDiGraph()
        self.__z_thresh = stats.norm.ppf(0.95)

    def get_ports_list(self) -> list:
        """Return a list of ports with high levels of network traffic."""
        common_ports = {80, 443, 53, 22, 3389, 8080}
        if not self.__df.empty and 'dport' in self.__df:
            top_ports = self.__df.groupby(
                'dport')['size'].sum().nlargest(10).index.astype(int).tolist()
            common_ports |= set(top_ports)
        return list(common_ports)

    def build_network_graph(self) -> None:
        """Creates a NetworkX MultiDiGraph with network connections representing edges
           and machines, which will be identified by their mac addresses, representing nodes.
           Edge attributes will store IP and network port information, as well as an edge weight
           that measures bytes."""
        for _, row in self.__df.iterrows():
            self.__network_graph.add_edge(
                *(str(row["src_mac"]), str(row["dst_mac"])),
                ip_src=row["source"],
                ip_dst=row["destination"],
                sport=row["sport"],
                dport=row["dport"],
                weight=row["size"]
            )

    def get_network_graph_len(self) -> int:
        """Return the number of nodes in the network graph."""
        return len(self.__network_graph.nodes)

    def get_highest_weighted_out_degree_for_ports(self) -> dict:
        """Return a key:value pair where the key represents the port number and the value represents
           a tuple containing the mac address of the node and the out-degree score for that node
           with the most traffic over the port."""
        highest_out_deg = {}
        for port in self.__ports_list:
            if port in self.__df["dport"]:
                subgraph = self.create_protocol_subgraph(port)
                if subgraph:
                    out_deg = subgraph.out_degree(weight="weight")
                    sorted_deg = sorted(
                        out_deg, key=lambda x: (x[1], x[0]), reverse=True)
                    highest_out_deg[port] = sorted_deg[0]
        return highest_out_deg

    def find_nodes_with_high_traffic(self) -> list:
        """Identify nodes with statistically high incoming traffic across all monitored ports.
           Return a list of tuples containing the port and outlier nodes."""
        highest_in_degree = []
        for port in self.__ports_list:
            if port not in self.__df["dport"]:
                continue
            subgraph = self.create_protocol_subgraph(port)
            if not subgraph:
                continue
            in_degrees = list(subgraph.in_degree(weight="weight"))
            if len(in_degrees) < 2:
                continue
            scores = np.array([v[1] for v in in_degrees])
            outlier_nodes = [in_degrees[i][0] for i in
                             np.where(stats.zscore(scores) > self.__z_thresh)[0]]
            if outlier_nodes:
                highest_in_degree.append((port, outlier_nodes))
        return highest_in_degree

    def create_protocol_subgraph(self, port: int) -> nx.DiGraph:
        """Create a subgraph that contains only edges of a specified port."""
        o_edges = [(u, v, d) for u, v, d in self.__network_graph.edges(
            data=True) if d["dport"] == port]
        if len(o_edges) < 1:
            return None
        subgraph = nx.DiGraph()
        subgraph.add_edges_from(o_edges)
        return subgraph


async def test_processor_get_df():
    processor = PacketProcessor()
    await processor.process_packets(pcap_file)
    return processor.get_dataframe()


async def main():
    # Get the DataFrame by awaiting the async function
    df = await test_processor_get_df()
    print(f"DataFrame has {len(df)} rows and {len(df.columns)} columns")

    # Create the analyzer with the DataFrame
    threat_analyzer = ThreatAnalyzer(df)

    print(threat_analyzer.get_ports_list())
    threat_analyzer.build_network_graph()
    print(threat_analyzer.get_network_graph_len())
    print(len(threat_analyzer.create_protocol_subgraph(80)))
    print(threat_analyzer.get_highest_weighted_out_degree_for_ports())
    print(threat_analyzer.find_nodes_with_high_traffic())

if __name__ == '__main__':
    # Run the main async function
    asyncio.run(main())
