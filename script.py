import subprocess
import platform
import re
import argparse
import logging
import statistics
import sys

import matplotlib.pyplot as plt
import networkx as nx

IPV4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
HOP_RE = re.compile(r'^\s*(\d+)\s+')
RTT_RE = re.compile(r'(<\s*\d+|\d+(\.\d+)?)\s*ms')

def parse_traceroute_line(line):
    """
    Parse a single traceroute/tracert output line.
    Returns (hop_num:int or None, ip:str or '', rtts:list[float], timeouts:int)
    """
    hop_num = None
    m = HOP_RE.match(line)
    if m:
        hop_num = int(m.group(1))

    # Find IP (prefer parenthesized address like "host (1.2.3.4)" else raw ip)
    ip = ""
    paren_ip = re.search(r'\((\d{1,3}(?:\.\d{1,3}){3})\)', line)
    if paren_ip:
        ip = paren_ip.group(1)
    else:
        ip_match = IPV4_RE.search(line)
        if ip_match:
            ip = ip_match.group(1)

    # Extract RTTs (handle "<1 ms" and '*' timeouts)
    rtts = []
    timeouts = 0
    for token in RTT_RE.finditer(line):
        raw = token.group(1)
        if raw.startswith('<'):
            # treat "<1" as 0.5 ms approximate
            try:
                val = float(raw.lstrip('<').strip())
                rtts.append(max(0.1, val / 2.0))
            except Exception:
                rtts.append(0.5)
        else:
            try:
                rtts.append(float(raw))
            except:
                pass

    # Count '*' groups (common in traceroute when probes time out)
    timeouts = line.count('*')

    return hop_num, ip, rtts, timeouts

def label_trace_route_output(traceroute_lines, jump_factor=1.5, absolute_min_ms=10.0):
    """
    Analyze traceroute output lines and label hops that look suspicious (possible hidden hops/MPLS).
    Heuristic: if RTT jumps by > jump_factor compared to previous median and above absolute_min_ms,
    and hop number increased only by 1, mark as suspicious.
    Returns list of dicts: [{'hop':int,'line':str,'ip':str,'rtts':[], 'median_rtt':float, 'suspicious':bool, 'timeouts':int}]
    and a printable summary string.
    """
    labeled = []
    prev_medians = []
    prev_hop = 0

    for line in traceroute_lines:
        hop_num, ip, rtts, timeouts = parse_traceroute_line(line)
        if hop_num is None:
            # skip non-hop summary lines
            continue

        median = (sum(rtts) / len(rtts)) if rtts else 0.0
        suspicious = False

        if prev_medians and median > 0:
            prev_med = statistics.median(prev_medians)
            print(prev_med, median)
            # Hop increment check: if hop increased by exactly 1 (expected), but latency jump large -> suspicious
            if hop_num - prev_hop == 1 and median > jump_factor * prev_med and median > absolute_min_ms:
                suspicious = True

        labeled.append({
            'hop': hop_num,
            'line': line.strip(),
            'ip': ip,
            'rtts': rtts,
            'median_rtt': median,
            'suspicious': suspicious,
            'timeouts': timeouts,
        })

        # update history
        if median > 0:
            prev_medians.append(median)
        prev_hop = hop_num

    # Build printable summary
    lines_out = []
    for item in labeled:
        flag = "SUSPICIOUS" if item['suspicious'] else "normal"
        rtt_disp = f"{item['median_rtt']:.2f} ms" if item['median_rtt'] else ("*timeouts*" if item['timeouts'] else "n/a")
        lines_out.append(f"[{flag}] Hop {item['hop']:02d} {item['ip'] or '-'} {rtt_disp}  --  {item['line']}")

    return labeled, "\n".join(lines_out)

def run_traceroute(dest_ip, timeout=30):
    """
    Run system traceroute/tracert and return output lines.
    """
    try:
        if platform.system().lower() == 'windows':
            proc = subprocess.run(['tracert', '-d', dest_ip], capture_output=True, text=True, timeout=timeout)
        else:
            # Use numeric output to ease parsing (-n)
            proc = subprocess.run(['traceroute', '-n', dest_ip], capture_output=True, text=True, timeout=timeout)
        out = proc.stdout.splitlines()
        if proc.returncode != 0 and not out:
            logging.debug("Traceroute returned non-zero exit code; stderr: %s", proc.stderr.strip())
        return out
    except subprocess.TimeoutExpired:
        logging.error("Traceroute to %s timed out", dest_ip)
        return []

def visualize_traceroute_path(labeled_output, save_path=None, show=True):
    """
    Visualize the traceroute path as a directed graph. Suspicious hops/edges colored red.
    labeled_output: list of dicts produced by label_trace_route_output.
    """
    if not labeled_output:
        logging.info("No hops to visualize.")
        return

    G = nx.DiGraph()
    labels = {}
    node_colors = []
    edge_colors = []
    prev_hop = None

    for item in labeled_output:
        hop = item['hop']
        ip = item['ip'] or ''
        label = f"{hop}\n{ip}" if ip else f"{hop}"
        G.add_node(hop)
        labels[hop] = label
        node_colors.append('red' if item['suspicious'] else '#4CAF50')  # red suspicious, green normal

        if prev_hop is not None:
            # Edge suspicious if either end marked suspicious
            edge_susp = item['suspicious'] or next((x for x in labeled_output if x['hop']==prev_hop and x['suspicious']), False)
            G.add_edge(prev_hop, hop, suspicious=edge_susp)
        prev_hop = hop

    # Prepare edge list and colors
    edges = list(G.edges(data=True))
    edge_list = [(u, v) for (u, v, _) in edges]
    edge_colors = ['red' if d.get('suspicious') else '#999999' for (_, _, d) in edges]
    edge_styles = ['dashed' if d.get('suspicious') else 'solid' for (_, _, d) in edges]

    pos = nx.spring_layout(G, seed=42, k=0.6)
    plt.figure(figsize=(8, max(4, len(G) * 0.4)))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=700)
    # Draw edges in two passes to support styles
    for (u, v, d), style, color in zip(edges, edge_styles, edge_colors):
        nx.draw_networkx_edges(G, pos, edgelist=[(u, v)], style=style, width=2.5, edge_color=color, arrows=True)
    nx.draw_networkx_labels(G, pos, labels, font_size=10)
    plt.title("Traceroute Path (suspicious hops in red)")
    plt.axis("off")
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=150)
        logging.info("Saved visualization to %s", save_path)
    if show:
        plt.show()
    plt.close()

def main(argv=None):
    parser = argparse.ArgumentParser(description="Traceroute analysis and visualization (heuristic MPLS/hidden-hop detection).")
    parser.add_argument('--ips', default='ips.txt', help="File with one destination IP/hostname per line (default: ips.txt)")
    parser.add_argument('--save-dir', default=None, help="Directory to save visualizations (optional)")
    parser.add_argument('--no-show', action='store_true', help="Do not show matplotlib windows (useful when saving images only)")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(levelname)s: %(message)s')

    try:
        with open(args.ips) as f:
            dests = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        logging.error("IP file not found: %s", args.ips)
        sys.exit(1)

    for dest in dests:
        logging.info("Tracing %s ...", dest)
        lines = run_traceroute(dest)
        labeled, summary = label_trace_route_output(lines)
        logging.info("\n%s", summary)
        save_path = None
        if args.save_dir:
            # safe filename
            safe = re.sub(r'[^A-Za-z0-9._-]', '_', dest)
            save_path = f"{args.save_dir.rstrip('/\\')}\\traceroute_{safe}.png"
        visualize_traceroute_path(labeled, save_path=save_path, show=not args.no_show)

if __name__ == "__main__":
    main()