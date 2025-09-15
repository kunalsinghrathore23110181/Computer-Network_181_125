#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt

def analyze_results(csv_file="server_results.csv"):
    # Load CSV
    df = pd.read_csv("C:/Users/kunal/OneDrive/Desktop/dns_resolver/server_results.csv")

    print("✅ Loaded", len(df), "records from", csv_file)

    # --- Summary stats ---
    print("\n=== Top Queried Domains ===")
    print(df['domain'].value_counts().head(10))

    print("\n=== IP Usage ===")
    print(df['resolved_ip'].value_counts())

    # --- Plot: Top 10 domains ---
    plt.figure(figsize=(10, 5))
    df['domain'].value_counts().head(10).plot(kind="bar", color="skyblue")
    plt.title("Top 10 Queried Domains")
    plt.xlabel("Domain")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

    # --- Plot: Resolved IP distribution ---
    plt.figure(figsize=(6, 4))
    df['resolved_ip'].value_counts().plot(kind="pie", autopct="%1.1f%%")
    plt.title("Resolved IP Distribution")
    plt.ylabel("")
    plt.show()

    # --- Domain → IP mapping heatmap-like view ---
    pivot = pd.crosstab(df['domain'], df['resolved_ip'])
    print("\n=== Domain to IP Mapping Table ===")
    print(pivot)

    plt.figure(figsize=(8, 6))
    plt.imshow(pivot, cmap="Blues", aspect="auto")
    plt.colorbar(label="Count")
    plt.xticks(range(len(pivot.columns)), pivot.columns, rotation=45, ha="right")
    plt.yticks(range(len(pivot.index)), pivot.index)
    plt.title("Domain → IP Mapping Heatmap")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    analyze_results("server_results.csv")
