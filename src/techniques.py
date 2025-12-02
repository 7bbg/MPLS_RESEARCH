import re
import typing as t
import matplotlib.pyplot as plt

# --- Global Constants (Derived from Past Research Methodology) ---

# Maximum initial TTL used in most systems (for U-Turn signature)
MAX_INITIAL_TTL = 255 
# Minimum length for a suspected sequence of LSRs to be considered an LSP
MIN_LSP_LENGTH = 2 


# --- Data Structure for Pre-Parsed Hop Information ---

class Hop:
    """Represents the pre-parsed results for a single hop (router interface) in a path."""
    def __init__(self, index: int, ip: str, quoted_ttl: int, has_rfc4950: bool, 
                 lse_ttl_value: t.Optional[int], traceroute_ttl: int, ping_ttl: int, rtt: float = 0.0):
        self.hop_index = index
        self.ip_address = ip
        
        # Data collected from ICMP Time-Exceeded messages (Traceroute)
        self.quoted_ttl = quoted_ttl # TTL quoted in the ICMP Time-Exceeded message
        self.has_rfc4950_extension = has_rfc4950
        self.lse_ttl_value = lse_ttl_value  # Only present if has_rfc4950 is True
        self.traceroute_ttl = traceroute_ttl # The TTL value of the ICMP reply packet itself

        # Data collected from ICMP Echo Replies (Ping Probing)
        self.ping_ttl = ping_ttl

        # Analysis fields
        self.u_turn_delta = 0
        # Analysis flags/annotations
        self.is_suspicious = False
        self.tunnel_type = "IP Router"

    def __repr__(self):
        return (f"Hop {self.hop_index} ({self.ip_address}, Type: {self.tunnel_type})")


# --- 1. Detection Functions ---
def detect_qttl_signature(path: t.List[Hop]) -> t.List[dict]:
    """Detects Implicit Tunnels using the Quoted TTL signature."""
    detected: t.List[dict] = []
    lsp_sequence: t.List[Hop] = []

    for i in range(1, len(path)):
        current_hop, prev_hop = path[i], path[i - 1]

        # Skip TIMEOUT artifacts
        if current_hop.ip_address == "TIMEOUT" or prev_hop.ip_address == "TIMEOUT":
            continue

        if (not current_hop.has_rfc4950_extension) and (current_hop.quoted_ttl == prev_hop.quoted_ttl + 1):
            if not lsp_sequence:
                lsp_sequence.append(prev_hop)
            lsp_sequence.append(current_hop)
        else:
            if len(lsp_sequence) >= MIN_LSP_LENGTH:
                detected.append(
                    {
                        "type": "Implicit Tunnel (Q-TTL)",
                        "hops": [h.ip_address for h in lsp_sequence],
                    }
                )
            lsp_sequence = []

    if len(lsp_sequence) >= MIN_LSP_LENGTH:
        detected.append(
            {
                "type": "Implicit Tunnel (Q-TTL)",
                "hops": [h.ip_address for h in lsp_sequence],
            }
        )

    # Mark hops as suspicious
    for entry in detected:
        for hop_ip in entry["hops"]:
            for hop in path:
                if hop.ip_address == hop_ip:
                    hop.is_suspicious = True
                    hop.tunnel_type = "Implicit Tunnel (Q-TTL)"
                    break
    return detected


def estimate_opaque_length(path: t.List[Hop]) -> t.List[dict]:
    """Estimates the length of an Opaque Tunnel using RFC4950's LSE-TTL field on the Last Hop."""
    detected: t.List[dict] = []
    for i, current_hop in enumerate(path, start=0):
        if current_hop.has_rfc4950_extension and current_hop.lse_ttl_value is not None:
            lse_ttl_at_lh = current_hop.lse_ttl_value

            # Hidden_Hops = Initial_LSE_TTL - LSE_TTL_at_LH - 1
            hidden_hops = MAX_INITIAL_TTL - lse_ttl_at_lh - 1

            if hidden_hops > 0:
                ingress_ler_index = i - 1  # The hop before the last hop : Future investigation formula (i-hidden_hops-1)

                ingress_ler_ip = path[ingress_ler_index].ip_address if ingress_ler_index >= 0 else "Unknown"
            
                current_hop.is_suspicious = True
                current_hop.tunnel_type = f"Opaque Tunnel (LH, {hidden_hops} hidden hops)"

                print(f"Detected Opaque Tunnel: {hidden_hops} hidden hops between {ingress_ler_ip} and {current_hop.ip_address}")
                
                # Ingress LER
                detected.append(
                    {
                        "type": "Opaque Tunnel",
                        "hidden_hops": hidden_hops,
                        "ingress_ler": None,
                        "last_hop": ingress_ler_ip,
                    }
                )


                # Egress LER
                detected.append(
                    {
                        "type": "Opaque Tunnel",
                        "hidden_hops": hidden_hops,
                        "ingress_ler": ingress_ler_ip,
                        "last_hop": current_hop.ip_address,
                    }
                )
    return detected


def infer_invisible_tunnel(path: t.List[Hop], max_index: int) -> t.List[dict]:
    """
    Infers Invisible tunnels by:
    - detecting sequences of TIMEOUT hops between responding hops, and/or
    - observing hop index jumps > 1 between consecutive responding hops.
    """
    detected: t.List[dict] = []

    i = 0
    while i < len(path) - 1:
        # Skip TIMEOUT-only spans at the start
        if path[i].ip_address == "TIMEOUT":
            i += 1
            continue

        j = i + 1
        timeout_count = 0

        # Count contiguous timeouts
        while j < len(path) and path[j].ip_address == "TIMEOUT":
            timeout_count += 1
            j += 1

        if j < len(path):
            # gap by hop_index as secondary signal
            index_gap = path[j].hop_index - path[i].hop_index - 1
            hidden_hops = max(timeout_count, index_gap if index_gap > 0 else 0)

            if hidden_hops > 0:
                detected.append(
                    {
                        "type": "Invisible Tunnel",
                        "hidden_hops": hidden_hops,
                        "start_ip": path[i].ip_address,
                        "end_ip": path[j].ip_address,
                    }
                )

        i = max(j, i + 1)

    return detected


def detect_u_turn_signature(path: t.List[Hop]) -> t.List[dict]:
    """
    Detects Implicit Tunnels using the U-Turn signature.
    Looks for a sequence where u_turn_delta decreases by 2 at each step.
    """
    detected: t.List[dict] = []
    lsp_sequence: t.List[Hop] = []

    # Calculate u_turn_delta for each hop
    for hop in path:
        hop.u_turn_delta = hop.traceroute_ttl - hop.ping_ttl

    for i in range(1, len(path)):
        current_hop = path[i]
        prev_hop = path[i - 1]

        # Skip TIMEOUTs and hops with missing ping/traceroute TTLs
        if (
            current_hop.ip_address == "TIMEOUT"
            or prev_hop.ip_address == "TIMEOUT"
            or current_hop.ping_ttl == 0
            or current_hop.traceroute_ttl == 0
            or prev_hop.ping_ttl == 0
            or prev_hop.traceroute_ttl == 0
        ):
            if len(lsp_sequence) >= MIN_LSP_LENGTH:
                detected.append({
                    "type": "Implicit Tunnel (U-Turn)",
                    "hops": [h.ip_address for h in lsp_sequence],
                })
            lsp_sequence = []
            continue

        # Check for arithmetic progression (decrease by 2)
        if prev_hop.u_turn_delta - current_hop.u_turn_delta == 2:
            if not lsp_sequence:
                lsp_sequence.append(prev_hop)
            lsp_sequence.append(current_hop)
        else:
            if len(lsp_sequence) >= MIN_LSP_LENGTH:
                detected.append({
                    "type": "Implicit Tunnel (U-Turn)",
                    "hops": [h.ip_address for h in lsp_sequence],
                })
            lsp_sequence = []

    # Final check for a sequence at the end
    if len(lsp_sequence) >= MIN_LSP_LENGTH:
        detected.append({
            "type": "Implicit Tunnel (U-Turn)",
            "hops": [h.ip_address for h in lsp_sequence],
        })

    # Mark hops as suspicious
    for entry in detected:
        for hop_ip in entry["hops"]:
            for hop in path:
                if hop.ip_address == hop_ip:
                    hop.is_suspicious = True
                    hop.tunnel_type = "Implicit Tunnel (U-Turn)"
                    break
    return detected


# --- Helper: build trace_data for duplicate IP trigger ---
def to_trace_data(path: t.List[Hop]) -> t.List[t.Tuple[int, str, int]]:
    """
    Convert Hop list to (hop_count, ip_address, reply_ttl) tuples expected by the duplicate IP detector.
    TIMEOUT entries are skipped.
    """
    out: t.List[t.Tuple[int, str, int]] = []
    for hop in path:
        if isinstance(hop, Hop) and hop.ip_address != "TIMEOUT":
            out.append((hop.hop_index, hop.ip_address, hop.traceroute_ttl))
    return out


# --- Duplicate IP trigger detector (UHP mode) ---
def detect_duplicate_ip_trigger(
    trace_data: t.Union[t.List[t.Tuple[int, str, int]], t.List[Hop]]
) -> t.Optional[str]:
    """
    Detect a 'Duplicate IP Address' anomaly, indicating a hidden MPLS tunnel (UHP Mode).

    Accepts:
      - List of (hop_count, ip_address, reply_ttl) tuples, or
      - List of Hop objects (TIMEOUTs ignored).
    Returns:
      - Message string if detected, else None.
    """
    # If we get Hop objects, we can also flag them directly
    if trace_data and isinstance(trace_data[0], Hop):  # type: ignore[index]
        previous_ip: t.Optional[str] = None
        previous_hop: t.Optional[Hop] = None

        for hop in t.cast(t.List[Hop], trace_data):
            if hop.ip_address == "TIMEOUT":
                continue
            if previous_ip is not None and hop.ip_address == previous_ip:
                # Mark both hops as implicit (duplicate IP/UHP)
                if previous_hop is not None:
                    previous_hop.is_suspicious = True
                    previous_hop.tunnel_type = "Invisible Tunnel (Duplicate IP/UHP)"
                hop.is_suspicious = True
                hop.tunnel_type = "Invisible Tunnel (Duplicate IP/UHP)"

                return (
                    f"Duplicate IP Address detected at Hop {previous_hop.hop_index if previous_hop else '?'} "
                    f"and Hop {hop.hop_index}. IP: {hop.ip_address}. "
                    f"This strongly suggests an Invisible UHP tunnel."
                )
            previous_ip = hop.ip_address
            previous_hop = hop

        return None

    # Otherwise, treat as list of 3-tuples (hop_count, ip, ttl)
    data = t.cast(t.List[t.Tuple[int, str, int]], trace_data)
    previous_ip: t.Optional[str] = None

    for hop_count, current_ip, _ in data:
        if previous_ip is not None and current_ip == previous_ip:
            return (
                f"Duplicate IP Address detected at Hop {hop_count-1} and Hop {hop_count}. "
                f"IP: {current_ip}. This strongly suggests an Invisible UHP tunnel."
            )
        previous_ip = current_ip

    return None

# --- TTL-Shift (Pipe Mode) anomaly detector ---
def detect_ttl_shift_anomaly(
    trace_data: t.Union[t.List[t.Tuple[int, str, int]], t.List[Hop]]
) -> t.Optional[str]:
    """
    Analyzes traceroute data to detect a 'significant TTL shift' anomaly,
    indicating a hidden MPLS tunnel (Pipe Mode)(Returned TTL Latency Analysis).

    Accepts:
      - List of (hop_count, ip_address, reply_ttl) tuples, or
      - List of Hop objects (TIMEOUTs ignored).
    Flags both involved hops as Implicit if detected.
    """
    # Normalize input to a list of (hop_count, ip, reply_ttl) tuples
    if trace_data and isinstance(trace_data[0], Hop):  # type: ignore[index]
        hops = [h for h in t.cast(t.List[Hop], trace_data) if h.ip_address != "TIMEOUT"]
        data: t.List[t.Tuple[int, str, int]] = [(h.hop_index, h.ip_address, h.traceroute_ttl) for h in hops]
        hop_map = {h.hop_index: h for h in hops}
    else:
        data = t.cast(t.List[t.Tuple[int, str, int]], trace_data)
        hop_map = None

    if len(data) < 3:
        return None

    for i in range(1, len(data) - 1):
        hop_n = data[i]
        hop_n_plus_1 = data[i + 1]

        ttl_n = hop_n[2]
        ttl_n_plus_1 = hop_n_plus_1[2]
        ttl_drop = ttl_n - ttl_n_plus_1

        # Heuristic: minimal drop across an apparent multi-hop jump
        if 0 < ttl_drop < 3:
            msg = (
                f"Significant TTL Shift detected between Hop {hop_n[0]} ({hop_n[1]}) and "
                f"Hop {hop_n_plus_1[0]} ({hop_n_plus_1[1]}). Returned TTL only dropped by {ttl_drop}. "
                f"This suggests a block of hidden hops."
            )
            # If we have Hop objects, mark both as invisible
            if hop_map is not None:
                h1 = hop_map.get(hop_n[0])
                h2 = hop_map.get(hop_n_plus_1[0])
                if h1:
                    h1.is_suspicious = True
                    h1.tunnel_type = "Invisible Tunnel (TTL Shift)"
                if h2:
                    h2.is_suspicious = True
                    h2.tunnel_type = "Invisible Tunnel (TTL Shift)"
            return msg

    return None
