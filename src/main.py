import re
import typing as t
from pathlib import Path
import matplotlib.pyplot as plt
import networkx as nx
import json
import scipy
from techniques import (
    Hop,
    detect_qttl_signature,
    estimate_opaque_length,
    infer_invisible_tunnel,
    detect_duplicate_ip_trigger,
    detect_ttl_shift_anomaly,
    detect_u_turn_signature,
)

def analyze_and_flag_path(path: t.List[Hop]) -> t.Dict[str, t.Any]:
    """Runs all detection methods and updates hop flags."""
    # Pre-flag Explicit Tunnels (simplest: RFC 4950 ON + ttl-propagate ON)
    in_explicit_sequence = False
    for hop in path:
        if hop.has_rfc4950_extension and not hop.is_suspicious:
            hop.is_suspicious = True
            hop.tunnel_type = "Explicit Tunnel"
            in_explicit_sequence = True
        elif in_explicit_sequence and not hop.has_rfc4950_extension:
            # End of the explicit tunnel sequence
            in_explicit_sequence = False

    # 1) Detect Implicit Tunnels (Q-TTL)
    implicit_results = detect_qttl_signature(path)

    # 2) Estimate Opaque Tunnels
    opaque_results = estimate_opaque_length(path)

    # 3) Infer Invisible Tunnels (Requires Hop Index)
    max_index = max(h.hop_index for h in path) if path else 0
    invisible_results = infer_invisible_tunnel(path, max_index)

    # 4) Detect Duplicate IP trigger (UHP) - pass Hop list so we can mark the hops
    dup_msg = detect_duplicate_ip_trigger(path)
    if dup_msg:
        print(dup_msg)

    # 5) Detect TTL Shift anomaly (Pipe Mode)
    ttl_shift_msg = detect_ttl_shift_anomaly(path)
    if ttl_shift_msg:
        print(ttl_shift_msg)

    # 6) Detect U-Turn signature
    u_turn_results = detect_u_turn_signature(path)

    # Summarize all results
    all_results = {
        "Implicit (Q-TTL)": implicit_results,
        "Opaque": opaque_results,
        "Invisible": invisible_results,
    }
    if dup_msg:
        all_results["Duplicate IP Trigger"] = dup_msg
    if ttl_shift_msg:
        all_results["TTL Shift Anomaly"] = ttl_shift_msg
    if u_turn_results:
        all_results["Implicit (U-Turn)"] = u_turn_results

    # Flag Invisible Tunnels (informational)
    for res in invisible_results:
        print(
            f"Warning: Possible {res['type']} between {res['start_ip']} and {res['end_ip']} "
            f"(Hiding {res['hidden_hops']} hops)"
        )

    print("\n--- Summary of Suspicious Hops ---")
    suspicious_hops = [hop for hop in path if hop.is_suspicious]
    for hop in suspicious_hops:
        print(f"Hop {hop.hop_index} ({hop.ip_address}): Marked as '{hop.tunnel_type}'")

    return all_results


# --- 3. Visualization ---

def plot_path_results(
    path: t.List[Hop],
    path_title: str,
    save_path: str = None,
    analysis_results: t.Dict[str, t.Any] = None,
) -> None:
    """Creates a network-like visualization of the path, highlighting detected tunnels."""
    G = nx.DiGraph()
    labels: t.Dict[int, str] = {}
    node_colors: t.List[str] = []

    # Build nodes/edges
    for i, current_hop in enumerate(path):
        G.add_node(current_hop.hop_index, ip=current_hop.ip_address)
        labels[current_hop.hop_index] = f"{current_hop.hop_index}\n{current_hop.ip_address}"

        # Color by detection
        if current_hop.tunnel_type.startswith("Explicit"):
            node_colors.append("red")
        elif current_hop.tunnel_type.startswith("Implicit"):
            node_colors.append("orange")
        elif current_hop.tunnel_type.startswith("Opaque"):
            node_colors.append("blue")
        elif current_hop.tunnel_type.startswith("Invisible"):
            node_colors.append("purple")
        else:
            node_colors.append("lightgray")

        # Add edge to next hop if next hop responded (skip TIMEOUT edges)
        if i < len(path) - 1:
            next_hop = path[i + 1]
            # if next_hop.ip_address != "TIMEOUT":
            #     G.add_edge(current_hop.hop_index, next_hop.hop_index)
            G.add_edge(current_hop.hop_index, next_hop.hop_index)

    # Add inferred tunnel edges (Invisible/Opaque)
    ip_to_nodes: t.Dict[str, t.List[int]] = {}
    for node_id, data in G.nodes(data=True):
        ip_to_nodes.setdefault(data.get("ip"), []).append(node_id)

    # FIX: correct keys ("Invisible"/"Opaque"), not "invisible_results"/"opaque_results"
    if analysis_results:
        for result in analysis_results.get("Invisible", []):
            start_nodes = ip_to_nodes.get(result["start_ip"], [])
            end_nodes = ip_to_nodes.get(result["end_ip"], [])
            if start_nodes and end_nodes:
                G.add_edge(start_nodes[0], end_nodes[0], color="purple", style="dashed", weight=3)

        for result in analysis_results.get("Opaque", []):
            ler_nodes = ip_to_nodes.get(result["ingress_ler"], [])
            lh_nodes = ip_to_nodes.get(result["last_hop"], [])
            if ler_nodes and lh_nodes:
                G.add_edge(ler_nodes[0], lh_nodes[0], color="blue", style="dashed", weight=3)

    # Use layout for a network-like appearance
    pos = nx.kamada_kawai_layout(G, weight='weight')

    plt.figure(figsize=(12, 8))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1500, alpha=0.8)
    nx.draw_networkx_labels(G, pos, labels, font_size=9, font_weight="bold")

    # Edge styles/colors
    edge_colors = [G[u][v].get("color", "gray") for u, v in G.edges()]
    edge_styles = [G[u][v].get("style", "solid") for u, v in G.edges()]
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, style=edge_styles, width=2)


    plt.title(path_title)
    
    legend_elements = [
        plt.Line2D([0], [0], marker="o", color="w", label="Explicit Tunnel (TTL Propagate ON, RFC 4950 ON)", markerfacecolor="red", markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Implicit Tunnel (TTL Propagate ON, RFC 4950 OFF)", markerfacecolor="orange", markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Opaque Tunnel (TTL Propagate OFF, RFC 4950 ON)", markerfacecolor="blue", markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Invisible Tunnel(Duplicate IP/UHP)", markerfacecolor="purple", markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Normal IP Router", markerfacecolor="lightgray", markersize=10),
        plt.Line2D([0], [0], color="purple", linestyle="--", lw=2, label="Invisible Tunnel Inferred Path"),
    ]
    plt.legend(handles=legend_elements, loc="upper right", frameon=True, bbox_to_anchor=(1.05, 1.0))

    plt.axis("off")
    plt.tight_layout()

    if save_path:
        project_root = Path(__file__).resolve().parents[1]  # ...\research_mpls_pract
        print(f"project_root: {project_root}")
        out_path = Path(save_path)
        print(f"out_path: {out_path}")

        # Treat relative paths as relative to project root (not CWD)
        if not out_path.is_absolute():
            out_path = project_root / out_path

        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path, dpi=150)
    plt.show()
    plt.close()



def load_trace_from_json(json_path: str) -> t.List[Hop]:
    """
    Loads a traceroute JSON file and returns a list of Hop objects.

    Supports:
      1) "clean" scamper-like wrapper: {"events":[..., {"type":"trace","hops":[...]} , ...]}
      2) single trace object: {"type":"trace","hops":[...]}
    """
    with open(json_path, "r") as f:
        obj = json.load(f)

    # Case 1: wrapper with events
    trace_obj: t.Optional[dict] = None
    if isinstance(obj, dict) and "events" in obj and isinstance(obj["events"], list):
        for ev in obj["events"]:
            if isinstance(ev, dict) and ev.get("type") == "trace" and "hops" in ev:
                trace_obj = ev
                break
    # Case 2: direct trace
    if trace_obj is None and isinstance(obj, dict) and obj.get("type") == "trace" and "hops" in obj:
        trace_obj = obj

    if trace_obj is None:
        raise ValueError(f"Unrecognized trace JSON format in {json_path}")

    hops: t.List[Hop] = []
    for i, hop in enumerate(trace_obj.get("hops", []), 1):
        ip = hop.get("addr", "TIMEOUT")
        quoted_ttl = hop.get("icmp_q_ttl", 0)

        has_rfc4950 = False
        lse_ttl_value = None
        if hop.get("icmpext"):
            for ext in hop["icmpext"]:
                if ext.get("mpls_labels"):
                    has_rfc4950 = True
                    lse_ttl_value = ext["mpls_labels"][0].get("mpls_ttl")
                    break

        traceroute_ttl = hop.get("reply_ttl", 0)
        ping_ttl = 0  # still not available from current datasets
        rtt = hop.get("rtt", 0.0)
        hops.append(Hop(i, ip, quoted_ttl, has_rfc4950, lse_ttl_value, traceroute_ttl, ping_ttl, rtt))

    return hops

# --- Use the data instead of the simulated path ---
if __name__ == "__main__":
    print("--- Running Integrated MPLS Tunnel Analysis Script on results.json ---")
    path_data = load_trace_from_json("data/traceroute1_clean.json")
    print(path_data)
    analysis_results = analyze_and_flag_path(path_data)
    plot_path_results(path_data, path_title="Path Visualization with Detected MPLS Tunnels", save_path="data/path_visualization_network.png", analysis_results=analysis_results)