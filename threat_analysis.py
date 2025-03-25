import networkx as nx
from scapy.all import rdpcap, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dot11 import Dot11
from scipy import stats
import numpy as np

pcap = "network_sim.pcap"


def get_mac_addresses(packet):
    if Ether in packet:
        mac_src, mac_dst = packet[Ether].src, packet[Ether].dst
    elif Dot11 in packet:
        mac_src, mac_dst = packet[Dot11].src, packet[Dot11].dst
    else:
        mac_src, mac_dst = "Unknown", "Unknown"
    return mac_src, mac_dst


net_graph = nx.MultiDiGraph()
packets = rdpcap(pcap)
for packet in packets:
    if not IP in packet:
        continue
    mac_src, mac_dst = get_mac_addresses(packet)
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    w = packet[IP].len
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    else:
        continue
    net_graph.add_edge(
        *(str(mac_src), str(mac_dst)),
        ip_src=ip_src,
        ip_dst=ip_dst,
        sport=sport,
        dport=dport,
        weight=w
    )

print(len(net_graph.nodes))


def protocol_subgraph(G, port):
    o_edges = [(u, v, d)
               for u, v, d in G.edges(data=True) if d["dport"] == port]
    if len(o_edges) < 1:
        return None
    subgraph = nx.DiGraph()
    subgraph.add_edges_from(o_edges)
    return subgraph


print(len(protocol_subgraph(net_graph, 80)))


psi = [80, 2503, 55553, 443]
for proto in psi:
    dG = protocol_subgraph(net_graph, proto)
    out_deg = dG.out_degree(weight='weight')
    sorted_deg = sorted(out_deg, key=lambda x: (x[1], x[0]), reverse=True)
    print(proto, sorted_deg[0])


protoG = protocol_subgraph(net_graph, 80)
in_deg = list(protoG.in_degree(weight='weight'))
scores = np.array([v[1] for v in in_deg])
z_thresh = stats.norm.ppf(0.95)
in_degree_z = stats.zscore(scores)
outlier_idx = list(np.where(in_degree_z > z_thresh)[0])
nodes = [in_deg[i][0] for i in outlier_idx]
print(nodes)

dirG = nx.DiGraph()
dirG.add_edges_from(net_graph.edges(data=True))
out_deg = dirG.out_degree()
out_deg = sorted(out_deg, key=lambda x: (x[1], x[0]), reverse=True)
u, score = out_deg[0]
print(u, score)


def exchange_ratios(G):
    res = []
    for u in G.nodes.keys():
        out_edges = G.out_edges(u, data=True)
        in_edges = G.in_edges(u, data=True)
        if len(out_edges) > 0:
            out_w = 1 + sum([d["weight"] for u, v, d in out_edges])
        else:
            out_w = 1
        if len(in_edges) > 0:
            in_w = 1 + sum([d["weight"] for u, v, d in in_edges])
        else:
            in_w = 1
        ier = in_w / out_w
        res.append((u, ier))
    return sorted(res, key=lambda x: (x[1], x[0]))


ier_scores = exchange_ratios(net_graph)
z_thresh = round(stats.norm.ppf(0.99), 3)
ier_z = stats.zscore([s[1] for s in ier_scores])
outlier_idx = list(np.where(ier_z > z_thresh)[0])
ier_outliers = [ier_scores[i] for i in outlier_idx]
print(ier_outliers)
