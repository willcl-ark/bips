"""Plot reciprocal visibility under independent, uniformly sampled caches.

Run: python3 bip-holepunch-v6/plot_mutual_discovery.py
Requires NumPy and Matplotlib. Outputs are written beside this script.
This is a discovery model, not a simulation of Bitcoin address relay or TCP.
"""

import csv
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter


def mutual_probability(nodes, retained):
    """Probability a node has at least one reciprocally retained peer."""
    if retained == nodes - 1:
        return 1.0
    return -math.expm1(retained * math.log1p(-retained / (nodes - 1)))


def required_retention(nodes, probability):
    """Smallest integer cache size reaching the requested probability."""
    low, high = 0, nodes - 1
    while low < high:
        mid = (low + high) // 2
        if mutual_probability(nodes, mid) >= probability:
            high = mid
        else:
            low = mid + 1
    return low


def main():
    output = Path(__file__).resolve().parent
    node_counts = np.unique(np.geomspace(100, 1_000_000, 401).astype(int))
    cache_sizes = np.unique(np.geomspace(1, 4096, 321).astype(int))
    probabilities = np.full((len(cache_sizes), len(node_counts)), np.nan)
    for j, nodes in enumerate(node_counts):
        for i, retained in enumerate(cache_sizes):
            if retained <= nodes - 1:
                probability = mutual_probability(nodes, retained)
                probabilities[i, j] = probability * 100

    with (output / "mutual-discovery.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("nodes", "retained", "probability_any_mutual",
                         "expected_fraction_of_cache_reciprocated",
                         "expected_mutual_candidates"))
        for nodes in (100, 1000, 10_000, 100_000, 1_000_000):
            for retained in (8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096):
                if retained <= nodes - 1:
                    writer.writerow((nodes, retained, mutual_probability(nodes, retained),
                                     retained / (nodes - 1), retained**2 / (nodes - 1)))

    targets = (0.50, 0.90, 0.99)
    with (output / "retention-thresholds.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("nodes", "retained_for_50_percent",
                         "retained_for_90_percent", "retained_for_99_percent"))
        for nodes in (100, 1000, 10_000, 100_000, 1_000_000):
            writer.writerow((nodes, *(required_retention(nodes, p) for p in targets)))

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "axes.titleweight": "bold", "svg.hashsalt": "holepunch-v6"})
    fig, (heatmap, thresholds) = plt.subplots(
        1, 2, figsize=(15, 7.5), gridspec_kw={"width_ratios": (1.35, 1)})
    fig.subplots_adjust(left=0.07, right=0.97, bottom=0.22, top=0.80, wspace=0.32)
    fig.suptitle("Mutual discovery from address gossip", x=0.07, y=0.97,
                 ha="left", fontsize=23, weight="bold")
    fig.text(0.07, 0.90, "Independent uniform caches | IPv4 hole-punching design v6 | "
             "Discovery opportunities, before connection attempts", color="#4b5563")

    heatmap.set_facecolor("#e5e7eb")
    mesh = heatmap.pcolormesh(node_counts, cache_sizes, probabilities,
                             cmap="viridis", vmin=0, vmax=100, shading="nearest",
                             rasterized=True)
    contours = heatmap.contour(node_counts, cache_sizes, probabilities,
                               levels=(10, 50, 90, 99), colors="white", linewidths=0.8)
    heatmap.clabel(contours, fmt="%g%%", fontsize=9)
    colorbar = fig.colorbar(mesh, ax=heatmap, pad=0.025, fraction=0.045)
    colorbar.set_label("Nodes with at least one mutual candidate (%)")
    heatmap.set_title("Chance of having a mutually known peer", loc="left", pad=15)
    heatmap.set_ylabel("Advertisements retained per node, m")
    heatmap.set_ylim(1, 4096)
    heatmap.text(125, 1800, "m > N − 1", color="#4b5563", fontsize=10)
    heatmap.scatter((10_000,), (32,), s=65, color="#fb7185",
                    edgecolor="white", linewidth=1.2, zorder=5)
    heatmap.annotate("10,000 nodes · 32 retained\n9.75% have a mutual candidate",
                    xy=(10_000, 32), xytext=(2200, 3.5), color="white", fontsize=10,
                    arrowprops={"arrowstyle": "-", "color": "white"},
                    bbox={"facecolor": "#172554", "alpha": 0.9, "edgecolor": "none", "pad": 6})

    colors = ("#3b82f6", "#059669", "#b45309")
    for probability, color in zip(targets, colors):
        required = [required_retention(int(nodes), probability) for nodes in node_counts]
        thresholds.plot(node_counts, required, color=color, linewidth=2.3,
                        label=f"{probability:.0%} of nodes")
        point = required_retention(10_000, probability)
        thresholds.scatter((10_000,), (point,), color=color, s=28, zorder=3)
        thresholds.annotate(f"{point} retained", (10_000, point), xytext=(8, 3),
                            textcoords="offset points", color=color, fontsize=10)
    thresholds.set_title("Retention needed for expected coverage", loc="left", pad=15)
    thresholds.set_ylabel("Minimum advertisements retained per node")
    thresholds.set_ylim(5, 4096)
    thresholds.grid(True, which="major", color="#d1d5db", linewidth=0.6)
    thresholds.legend(loc="upper left", frameon=False)
    for axis in (heatmap, thresholds):
        axis.set_xscale("log")
        axis.set_yscale("log")
        axis.set_xlim(100, 1_000_000)
        axis.set_xlabel("Participating nodes, N")
        axis.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x:,.0f}"))
        axis.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:,.0f}"))
        axis.spines[["top", "right"]].set_visible(False)
    heatmap.set_yticks((1, 4, 16, 64, 256, 1024, 4096))
    thresholds.set_yticks((10, 32, 100, 320, 1000, 3200))

    fig.text(0.07, 0.11, r"$P(\geq 1\ \mathrm{mutual}) = 1 - (1 - m/(N-1))^m$"
             "     Each node independently retains m distinct peers from the other N − 1.", fontsize=12)
    fig.text(0.07, 0.06, "Snapshot model: all advertisements are valid and overlap in time. "
             "Actual gossip is correlated. No Sybils, selection, capacity, clock, or NAT losses are modeled.",
             fontsize=10, color="#4b5563")
    for extension in ("png", "svg"):
        path = output / f"mutual-discovery.{extension}"
        fig.savefig(path, dpi=180,
                    metadata={"Date": None} if extension == "svg" else None)
        if extension == "svg":
            # Matplotlib emits trailing spaces in SVG paths.
            path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n")
    plt.close(fig)
    print((output / "retention-thresholds.csv").read_text(), end="")
    print(f"P(any mutual), N=10000, m=32: {mutual_probability(10_000, 32):.8%}")


if __name__ == "__main__":
    main()
