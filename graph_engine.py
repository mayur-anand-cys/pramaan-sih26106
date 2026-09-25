import networkx as nx
import plotly.graph_objects as go
from typing import Dict, List, Any

def build_threat_infrastructure_graph(
    from_header: str,
    return_path: str,
    urls: List[str],
    geo_data: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Construct a NetworkX Directed Threat Infrastructure Graph:
    EMAIL -> DOMAIN -> IP -> ASN -> URL
    Returns nodes, edges, summary stats, and Plotly figure for UI rendering.
    """
    G = nx.DiGraph()

    # Helper to clean email domain
    def get_domain(addr: str) -> str:
        if "@" in addr:
            return addr.split("@")[-1].strip("> ").strip().lower()
        return addr.strip().lower()

    sender_email = from_header if from_header else "Unknown Sender"
    sender_domain = get_domain(from_header)
    return_domain = get_domain(return_path)

    # 1. Add Core Email Node
    G.add_node(sender_email, type="EMAIL", label=f"Sender Email:\n{sender_email[:30]}")

    # 2. Add Domain Nodes
    if sender_domain:
        G.add_node(sender_domain, type="DOMAIN", label=f"From Domain:\n{sender_domain}")
        G.add_edge(sender_email, sender_domain, relation="HAS_FROM_DOMAIN")

    if return_domain and return_domain != sender_domain:
        G.add_node(return_domain, type="DOMAIN", label=f"Return Domain:\n{return_domain}")
        G.add_edge(sender_email, return_domain, relation="USES_RETURN_PATH")

    # 3. Add IP and ASN Nodes
    for geo in geo_data:
        ip_addr = geo.get("ip")
        if not ip_addr:
            continue

        isp_asn = geo.get("asn", geo.get("isp", "Unknown ISP"))
        G.add_node(ip_addr, type="IP", label=f"IP: {ip_addr}")
        
        if sender_domain:
            G.add_edge(sender_domain, ip_addr, relation="ORIGIN_IP")

        if isp_asn and isp_asn != "N/A":
            G.add_node(isp_asn, type="ASN", label=f"ASN/ISP:\n{isp_asn[:25]}")
            G.add_edge(ip_addr, isp_asn, relation="BELONGS_TO_ASN")

    # 4. Add URL Nodes
    for idx, u in enumerate(urls, 1):
        url_label = f"URL #{idx}:\n{u[:35]}..." if len(u) > 35 else f"URL #{idx}:\n{u}"
        G.add_node(u, type="URL", label=url_label)
        G.add_edge(sender_email, u, relation="CONTAINS_URL")

        # Connect URL to its hostname domain if applicable
        from urllib.parse import urlparse
        u_domain = urlparse(u if "://" in u else "http://" + u).hostname
        if u_domain:
            G.add_node(u_domain, type="DOMAIN", label=f"URL Domain:\n{u_domain}")
            G.add_edge(u, u_domain, relation="TARGETS_DOMAIN")

    return {
        "graph": G,
        "num_nodes": G.number_of_nodes(),
        "num_edges": G.number_of_edges(),
        "nodes": [{"id": n, "data": G.nodes[n]} for n in G.nodes()],
        "edges": [{"source": u, "target": v, "data": G.edges[u, v]} for u, v in G.edges()]
    }

def generate_plotly_threat_graph(graph_data: Dict[str, Any]) -> go.Figure:
    """
    Generate an interactive Plotly 2D Network Graph figure from graph data.
    """
    G = graph_data["graph"]
    pos = nx.spring_layout(G, k=0.5, seed=42)

    # Color map by node type
    color_map = {
        "EMAIL": "#7dd3fc",   # Sky Blue
        "DOMAIN": "#fbbf6d",  # Amber / Warning
        "IP": "#e24b4a",      # Red / Danger
        "ASN": "#a78bfa",     # Purple / ISP
        "URL": "#ff5252"      # Crimson / URL
    }

    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#334155'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_colors = []
    node_text = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_type = G.nodes[node].get("type", "EMAIL")
        node_colors.append(color_map.get(node_type, "#7dd3fc"))
        node_text.append(f"{node_type}: {node}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[G.nodes[n].get("type", "") for n in G.nodes()],
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            showscale=False,
            color=node_colors,
            size=22,
            line=dict(width=2, color='#0b0d10')
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
         layout=go.Layout(
            title=dict(
                text="PRAMAAN Threat Infrastructure Entity Graph",
                font=dict(size=14, color='#f8fafc')
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor='#12151a',
            plot_bgcolor='#12151a'
        )
    )

    return fig
