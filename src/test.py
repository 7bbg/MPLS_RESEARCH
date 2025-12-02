from techniques import Hop
from main import analyze_and_flag_path, plot_path_results

# Simulated path data for testing
simulated_path_data = [
    Hop(1, "10.0.0.1", 64, False, None, 64, 64, rtt=5.0),
    Hop(2, "20.0.1.1", 65, False, None, 63, 63, rtt=6.0),
    Hop(3, "20.0.1.1", 66, False, None, 62, 62, rtt=7.0),
    Hop(4, "30.0.1.1", 67, True, 250, 61, 61, rtt=8.0),
    Hop(5, "30.0.1.2", 68, True, 250, 60, 60, rtt=9.0),
    Hop(6, "40.0.1.1", 59, True, 252, 59, 59, rtt=15.0),
    Hop(7, "50.0.1.1", 58, False, None, 58, 58, rtt=16.0),
    Hop(8, "TIMEOUT", 0, False, None, 0, 0, rtt=0.0),
    Hop(9, "60.0.1.1", 56, False, None, 56, 56, rtt=50.0),
    Hop(10, "70.0.1.1", 55, False, None, 55, 55, rtt=51.0),
]

if __name__ == "__main__":
    print("--- Test: MPLS Tunnel Analysis on Simulated Path Data ---")
    results = analyze_and_flag_path(simulated_path_data)
    print("Analysis Results:")
    print(results)
    plot_path_results(simulated_path_data, path_title="Test Path Visualization", save_path="data/path_visualization_network_test.png")