"""
Mininet topology for linear path with 4 routers (h1-r1-r2-r3-r4-h2).

To run:
    Note: I am using Windows Subsystem for Linux (WSL) with Ubuntu, so some commands may differ on native Linux or macOS.
    1) Install Mininet (if not already installed):
        sudo python3 -m pip install mininet
    2) Run this script with sudo (required for Mininet):
        sudo python3 mininet_linear_lab.py

"""


from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter(Node):
    """A Node with IP forwarding enabled (acts like a simple router)."""
    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

        # Determinism for traceroute/ICMP
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        self.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")
        self.cmd("sysctl -w net.ipv4.icmp_ratelimit=0")

        # Clear firewall rules inside the namespace
        self.cmd("iptables -F")
        self.cmd("iptables -t nat -F")
        self.cmd("iptables -t mangle -F")
        self.cmd("iptables -t raw -F")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()

def add_ip(node, intf, cidr):
    node.cmd(f"ip addr flush dev {intf}")
    node.cmd(f"ip addr add {cidr} dev {intf}")
    node.cmd(f"ip link set dev {intf} up")

def enable_mpls_kernel(node):
    """
    Best-effort: load MPLS modules + enable MPLS globally.
    Note: modules are global to the host kernel; running in any namespace is fine.
    """
    node.cmd("modprobe mpls_router || true")
    node.cmd("modprobe mpls_iptunnel || true")
    node.cmd("sysctl -w net.mpls.platform_labels=100000 >/dev/null 2>&1 || true")

def enable_mpls_input(node, intf_names):
    """
    Enable acceptance of MPLS-labeled packets on specific interfaces.
    Required for swap/pop on transit/egress routers.
    """
    for intf in intf_names:
        node.cmd(f"sysctl -w net.mpls.conf.{intf}.input=1 >/dev/null 2>&1 || true")
    node.cmd("sysctl -w net.mpls.conf.lo.input=1 >/dev/null 2>&1 || true")

def config_static_mpls_lsp(r1, r2, r3, r4):
    """
    Build two unidirectional static LSPs:
      h1(10.0.0.1) -> h2(10.0.0.18): labels 100/200/300 (push/swap/swap/pop)
      h2 -> h1: labels 400/500/600
    """
    # --- Enable MPLS kernel features (best effort) ---
    enable_mpls_kernel(r1)

    # --- Enable MPLS input on core-facing interfaces ---
    # Core interfaces:
    # r1: r1-eth1 (to r2)
    # r2: r2-eth0 (from r1), r2-eth1 (to r3)
    # r3: r3-eth0 (from r2), r3-eth1 (to r4)
    # r4: r4-eth0 (from r3)
    enable_mpls_input(r1, ["r1-eth1"])
    enable_mpls_input(r2, ["r2-eth0", "r2-eth1"])
    enable_mpls_input(r3, ["r3-eth0", "r3-eth1"])
    enable_mpls_input(r4, ["r4-eth0"])

    # --- Forward direction: r1 -> r2 -> r3 -> r4 (to h2=10.0.0.18) ---
    # Ingress push (r1): for traffic to h2, push label 100 towards r2 (10.0.0.6)
    r1.cmd("ip route replace 10.0.0.18/32 encap mpls 100 via 10.0.0.6 dev r1-eth1")

    # Transit swap:
    r2.cmd("ip -f mpls route replace 100 as 200 via inet 10.0.0.10 dev r2-eth1")
    r3.cmd("ip -f mpls route replace 200 as 300 via inet 10.0.0.14 dev r3-eth1")

    # Egress pop on r4 then deliver to h2 (directly connected)
    r4.cmd("ip -f mpls route replace 300 pop via inet 10.0.0.18 dev r4-eth1")

    # --- Reverse direction: r4 -> r3 -> r2 -> r1 (to h1=10.0.0.1) ---
    r4.cmd("ip route replace 10.0.0.1/32 encap mpls 400 via 10.0.0.13 dev r4-eth0")
    r3.cmd("ip -f mpls route replace 400 as 500 via inet 10.0.0.9 dev r3-eth0")
    r2.cmd("ip -f mpls route replace 500 as 600 via inet 10.0.0.5 dev r2-eth0")
    r1.cmd("ip -f mpls route replace 600 pop via inet 10.0.0.1 dev r1-eth0")

def main(hide_core_hops=False, loss_pct=0, enable_mpls=False):
    net = Mininet(link=TCLink, controller=None, autoSetMacs=True, autoStaticArp=True)

    info("*** Creating nodes\n")
    h1 = net.addHost("h1")
    h2 = net.addHost("h2")
    r1 = net.addHost("r1", cls=LinuxRouter)
    r2 = net.addHost("r2", cls=LinuxRouter)
    r3 = net.addHost("r3", cls=LinuxRouter)
    r4 = net.addHost("r4", cls=LinuxRouter)

    info("*** Creating links (line: h1-r1-r2-r3-r4-h2)\n")
    net.addLink(h1, r1, intfName1="h1-eth0", intfName2="r1-eth0", loss=loss_pct)
    net.addLink(r1, r2, intfName1="r1-eth1", intfName2="r2-eth0", loss=loss_pct)
    net.addLink(r2, r3, intfName1="r2-eth1", intfName2="r3-eth0", loss=loss_pct)
    net.addLink(r3, r4, intfName1="r3-eth1", intfName2="r4-eth0", loss=loss_pct)
    net.addLink(r4, h2, intfName1="r4-eth1", intfName2="h2-eth0", loss=loss_pct)

    info("*** Starting network\n")
    net.start()
    net.staticArp()

    info("*** Assigning IP addresses (/30 plan)\n")
    add_ip(h1, "h1-eth0", "10.0.0.1/30")
    add_ip(r1, "r1-eth0", "10.0.0.2/30")

    add_ip(r1, "r1-eth1", "10.0.0.5/30")
    add_ip(r2, "r2-eth0", "10.0.0.6/30")

    add_ip(r2, "r2-eth1", "10.0.0.9/30")
    add_ip(r3, "r3-eth0", "10.0.0.10/30")

    add_ip(r3, "r3-eth1", "10.0.0.13/30")
    add_ip(r4, "r4-eth0", "10.0.0.14/30")

    add_ip(r4, "r4-eth1", "10.0.0.17/30")
    add_ip(h2, "h2-eth0", "10.0.0.18/30")

    info("*** Setting default routes on hosts\n")
    h1.cmd("ip route replace default via 10.0.0.2")
    h2.cmd("ip route replace default via 10.0.0.17")

    info("*** Adding static routes on routers (IP fallback)\n")
    r1.cmd("ip route replace 10.0.0.16/30 via 10.0.0.6")
    r2.cmd("ip route replace 10.0.0.0/30 via 10.0.0.5")
    r2.cmd("ip route replace 10.0.0.16/30 via 10.0.0.10")
    r3.cmd("ip route replace 10.0.0.0/30 via 10.0.0.9")
    r3.cmd("ip route replace 10.0.0.16/30 via 10.0.0.14")
    r4.cmd("ip route replace 10.0.0.0/30 via 10.0.0.13")

    if enable_mpls:
        info("*** Configuring static MPLS LSPs (push/swap/pop)\n")
        config_static_mpls_lsp(r1, r2, r3, r4)

        info("*** MPLS quick verification commands\n")
        info(r1.cmd("ip route get 10.0.0.18"))
        info(r2.cmd("ip -f mpls route show || true"))
        info(r3.cmd("ip -f mpls route show || true"))
        info(r4.cmd("ip -f mpls route show || true"))

    if hide_core_hops:
        info("*** Hiding core hops by dropping ICMP Time Exceeded on r2 and r3\n")
        for r in (r2, r3):
            r.cmd("iptables -F")
            r.cmd("iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j DROP")

    info("*** Quick checks\n")
    info(h1.cmd("ping -c 2 10.0.0.18"))
    info(h1.cmd("traceroute -I -n -q 2 -w 2 10.0.0.18"))

    info("*** Starting Mininet CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    # For MPLS: set enable_mpls=True
    main(hide_core_hops=True, loss_pct=0, enable_mpls=True)