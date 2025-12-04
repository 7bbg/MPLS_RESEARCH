# MPLS Tunnel Detection & Visualization

This project analyzes network paths to detect and visualize MPLS(Multiprotocol Label Switching) tunnels (Explicit, Implicit, Opaque, Invisible) using traceroute and ping data.

## Features

- Detects MPLS tunnel types using TTL, RFC4950, duplicate IP, and other signatures
- Visualizes network paths and tunnels with matplotlib & networkx
- Supports real traceroute JSON data and simulated test data
- Includes test script for validation

## Usage

1. Install requirements:
   ```
   pip install -r requirements.txt
   ```

2. Run analysis on data:
   ```
   python src/main.py
   ```

3. Run test with simulated data:
   ```
   python src/test.py
   ```

## Data

- Place traceroute JSON files in the `data/` directory.
- Simulated test data is included in `src/test.py`.

## Output

- Analysis results printed to console
- Path visualizations saved as PNG in `data/`

## Requirements

- Python 3.x
- matplotlib
- networkx

## Files

- `src/main.py` – Main analysis and visualization script
- `src/techniques.py` – Detection logic
- `src/test.py` – Test script with simulated data
- `data/` – Input and output data files

## References

1. RFC 4950
2. RFC 3031
3. Van Aubel, Y., Luttringer, J.-R., Mérindol, P., Pansiot, J.-J., & Donnet, B. (Year). TNT, Watch me Explode: A Light in the Dark for Revealing MPLS Tunnels.
4. Revealing MPLS tunnels obscured from traceroute, B. Donnet, M. Luckie, P. Merindol, J-J Pansiot
