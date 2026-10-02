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

def build_campaign_graph(campaign_id: str) -> Dict[str, Any]:
    """
    Load a Neo4j campaign subgraph and convert it into the same dict shape
    that build_threat_infrastructure_graph() returns, so the existing
    generate_plotly_threat_graph() can render it without modification.

    Accepts campaign IDs in any of the formats:
      - "CAMP-001"     (from neo4j_engine.correlate_campaigns)
      - "0042"         (numeric shortcut — tries "CAMP-0042" as fallback)
      - anything else  (passed through verbatim)
    """
    try:
        from backend.graph.queries import get_campaign_graph
    except Exception as e:
        return {
            "graph": nx.DiGraph(),
            "num_nodes": 0,
            "num_edges": 0,
            "nodes": [],
            "edges": [],
            "campaign_id": campaign_id,
            "error": f"campaign query unavailable: {e}",
        }

    # Try the given id, then "CAMP-<zero-padded>" as a fallback
    cg = get_campaign_graph(campaign_id)
    if not cg or not cg.get("nodes"):
        try:
            padded = f"CAMP-{int(campaign_id):03d}"
            alt = get_campaign_graph(padded)
            if alt and alt.get("nodes"):
                cg = alt
                campaign_id = padded
        except (ValueError, TypeError):
            pass

    if not cg or not cg.get("nodes"):
        return {
            "graph": nx.DiGraph(),
            "num_nodes": 0,
            "num_edges": 0,
            "nodes": [],
            "edges": [],
            "campaign_id": campaign_id,
        }

    G = nx.DiGraph()

    for n in cg.get("nodes", []):
        nid = n.get("id")
        if not nid:
            continue
        ntype = n.get("type", "Email").upper()
        nlabel = n.get("label", nid)
        G.add_node(nid, type=ntype, label=nlabel)

    for e in cg.get("edges", []):
        src_id = e.get("source")
        tgt_id = e.get("target")
        if not src_id or not tgt_id:
            continue
        # Ensure referenced nodes exist
        if src_id not in G:
            G.add_node(src_id, type="UNKNOWN", label=src_id)
        if tgt_id not in G:
            G.add_node(tgt_id, type="UNKNOWN", label=tgt_id)
        G.add_edge(src_id, tgt_id, relation=e.get("label", ""))

    return {
        "graph": G,
        "num_nodes": G.number_of_nodes(),
        "num_edges": G.number_of_edges(),
        "nodes": [{"id": n, "data": dict(G.nodes[n])} for n in G.nodes()],
        "edges": [
            {"source": u, "target": v, "data": dict(G.edges[u, v])}
            for u, v in G.edges()
        ],
        "campaign_id": campaign_id,
    }


def generate_plotly_threat_graph(graph_data: Dict[str, Any]) -> go.Figure:
    """
    Generate an interactive Plotly 3D Network Graph figure.

    Z-axis depth by node type so infrastructure layers stack vertically:
        EMAIL  -> z = 0
        DOMAIN -> z = 1
        URL    -> z = 2
        IP     -> z = 3
        ASN    -> z = 4
    """
    G = graph_data["graph"]
    pos = nx.spring_layout(G, k=0.5, iterations=20, seed=42, dim=3)

    color_map = {
        "EMAIL": "#7dd3fc",
        "DOMAIN": "#fbbf6d",
        "IP": "#e24b4a",
        "ASN": "#a78bfa",
        "URL": "#ff5252",
    }

    # --- edge traces (lines connecting nodes) ---
    edge_x = []
    edge_y = []
    edge_z = []
    for edge in G.edges():
        x0, y0, z0 = pos[edge[0]]
        x1, y1, z1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_z.extend([z0, z1, None])

    edge_trace = go.Scatter3d(
        x=edge_x, y=edge_y, z=edge_z,
        mode="lines",
        line=dict(width=2, color="#334155"),
        hoverinfo="none",
    )

    # --- node trace ---
    node_x = []
    node_y = []
    node_z = []
    node_colors = []
    node_hover = []
    node_labels = []

    for node in G.nodes():
        x, y, z = pos[node]
        node_type = G.nodes[node].get("type", "EMAIL")
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)
        node_colors.append(color_map.get(node_type, "#7dd3fc"))
        node_labels.append(node_type)
        node_hover.append("<b>Type:</b> " + str(node_type) + "<br><b>Value:</b> " + str(node))

    node_trace = go.Scatter3d(
        x=node_x, y=node_y, z=node_z,
        mode="markers+text",
        text=node_labels,
        textposition="top center",
        textfont=dict(size=9, color="#e2e8f0"),
        hovertext=node_hover,
        hoverinfo="text",
        marker=dict(
            size=8,
            color=node_colors,
            line=dict(width=1, color="#0b0d10"),
            opacity=0.95,
        ),
    )

    # --- camera / scene layout ---
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(
                text="PRAMAAN 3D Threat Infrastructure Graph",
                font=dict(size=14, color="#f8fafc"),
            ),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=10, l=5, r=5, t=40),
            scene=dict(
                xaxis=dict(
                    showgrid=False, zeroline=False, showticklabels=False,
                    title="", backgroundcolor="#12151a", showbackground=True,
                ),
                yaxis=dict(
                    showgrid=False, zeroline=False, showticklabels=False,
                    title="", backgroundcolor="#12151a", showbackground=True,
                ),
                zaxis=dict(
                    showgrid=True, zeroline=False,
                    title="Layer (Z)",
                    backgroundcolor="#12151a", showbackground=True,
                    gridcolor="#334155",
                    tickmode="array",
                    tickvals=[0, 1, 2, 3, 4],
                    ticktext=["Email", "Domain", "URL", "IP", "ASN"],
                    color="#94a3b8",
                ),
                camera=dict(
                    eye=dict(x=1.6, y=1.6, z=1.2),
                ),
            ),
            paper_bgcolor="#12151a",
        ),
    )

    return fig