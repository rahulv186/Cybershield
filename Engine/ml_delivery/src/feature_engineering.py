import pandas as pd
import numpy as np


DATA_PATH = "data/traintest.csv"


def load_data():
    """Load the CyberShield dataset."""
    df = pd.read_csv(DATA_PATH)

    print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

    return df


def is_private_ip(ip):
    """Return 1 if IP is a private/local IP address, otherwise 0."""
    if pd.isna(ip):
        return 0

    ip = str(ip)

    if ip.startswith("10."):
        return 1

    if ip.startswith("192.168."):
        return 1

    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            return int(16 <= second_octet <= 31)
        except (ValueError, IndexError):
            return 0

    return 0


def create_features(df):
    """Create ML-friendly numerical features from Zeek traffic metadata."""

    data = df.copy()

    # ---------------------------------------------------------
    # 1. Traffic volume features
    # ---------------------------------------------------------

    data["total_bytes"] = data["src_bytes"] + data["dst_bytes"]

    data["total_packets"] = data["src_pkts"] + data["dst_pkts"]

    data["byte_ratio"] = (
        data["src_bytes"] / (data["dst_bytes"] + 1)
    )

    data["packet_ratio"] = (
        data["src_pkts"] / (data["dst_pkts"] + 1)
    )

    data["bytes_per_packet"] = (
        data["total_bytes"] / (data["total_packets"] + 1)
    )

    data["src_dst_byte_difference"] = (
        data["src_bytes"] - data["dst_bytes"]
    )

    data["src_dst_packet_difference"] = (
        data["src_pkts"] - data["dst_pkts"]
    )

    data["outbound_byte_ratio"] = (
        data["src_bytes"] / (data["total_bytes"] + 1)
    )

    # ---------------------------------------------------------
    # 2. Traffic speed features
    # ---------------------------------------------------------

    data["bytes_per_second"] = (
        data["total_bytes"] / (data["duration"] + 0.001)
    )

    data["packets_per_second"] = (
        data["total_packets"] / (data["duration"] + 0.001)
    )

    # ---------------------------------------------------------
    # 3. Connection features
    # ---------------------------------------------------------

    failed_states = ["S0", "REJ", "RSTO", "RSTR"]

    data["is_failed_connection"] = (
        data["conn_state"].isin(failed_states).astype(int)
    )

    data["has_missed_bytes"] = (
        data["missed_bytes"] > 0
    ).astype(int)

    # ---------------------------------------------------------
    # 4. IP features
    # ---------------------------------------------------------

    data["src_is_private"] = (
        data["src_ip"].apply(is_private_ip)
    )

    data["dst_is_private"] = (
        data["dst_ip"].apply(is_private_ip)
    )

    # ---------------------------------------------------------
    # 5. Port features
    # ---------------------------------------------------------

    def port_category(port):
        if pd.isna(port):
            return "unknown"

        port = int(port)

        if port <= 1023:
            return "well_known"

        if port <= 49151:
            return "registered"

        return "dynamic"

    data["src_port_category"] = (
        data["src_port"].apply(port_category)
    )

    data["dst_port_category"] = (
        data["dst_port"].apply(port_category)
    )

    # ---------------------------------------------------------
    # 6. DNS features
    # ---------------------------------------------------------

    data["has_dns_query"] = (
        data["dns_query"].notna()
        & (data["dns_query"].astype(str) != "-")
    ).astype(int)

    data["dns_query_length"] = (
        data["dns_query"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    # ---------------------------------------------------------
    # 7. TLS / SSL features
    # ---------------------------------------------------------

    data["has_ssl"] = (
        data["ssl_version"].notna()
        & (data["ssl_version"].astype(str) != "-")
    ).astype(int)

    data["has_ssl_cipher"] = (
        data["ssl_cipher"].notna()
        & (data["ssl_cipher"].astype(str) != "-")
    ).astype(int)

    # Zeek commonly represents boolean fields as T/F
    data["ssl_resumed_flag"] = (
        data["ssl_resumed"].astype(str).str.upper() == "T"
    ).astype(int)

    data["ssl_established_flag"] = (
        data["ssl_established"].astype(str).str.upper() == "T"
    ).astype(int)

    # ---------------------------------------------------------
    # 8. HTTP features
    # ---------------------------------------------------------

    data["has_http"] = (
        data["http_method"].notna()
        & (data["http_method"].astype(str) != "-")
    ).astype(int)

    data["http_uri_length"] = (
        data["http_uri"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    data["http_user_agent_length"] = (
        data["http_user_agent"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    data["http_status_class"] = np.where(
        data["http_status_code"] > 0,
        data["http_status_code"] // 100,
        0
    )

    data["has_http_request_body"] = (
        data["http_request_body_len"] > 0
    ).astype(int)

    data["has_http_response_body"] = (
        data["http_response_body_len"] > 0
    ).astype(int)

    # ---------------------------------------------------------
    # 9. MIME / Weird features
    # ---------------------------------------------------------

    data["has_orig_mime"] = (
        data["http_orig_mime_types"].notna()
        & (data["http_orig_mime_types"].astype(str) != "-")
    ).astype(int)

    data["has_resp_mime"] = (
        data["http_resp_mime_types"].notna()
        & (data["http_resp_mime_types"].astype(str) != "-")
    ).astype(int)

    data["has_weird"] = (
        (
            data["weird_name"].notna()
            & (data["weird_name"].astype(str) != "-")
        )
        |
        (
            data["weird_notice"].notna()
            & (data["weird_notice"].astype(str) != "-")
        )
    ).astype(int)

    # ---------------------------------------------------------
    # 10. Remove fields that should NOT directly enter ML
    # ---------------------------------------------------------

    columns_to_drop = [
        # Raw IPs can cause overfitting
        "src_ip",
        "dst_ip",

        # Targets
        "label",
        "type",

        # High-cardinality text
        "dns_query",
        "ssl_subject",
        "ssl_issuer",
        "http_uri",
        "http_user_agent",
        "http_orig_mime_types",
        "http_resp_mime_types",
        "weird_addl",
        "weird_notice",
    ]

    data = data.drop(
        columns=columns_to_drop,
        errors="ignore"
    )

    return data


def prepare_binary_dataset(df):
    """
    Prepare dataset for:
    Normal (0) vs Attack (1)
    """

    X = create_features(df)

    y = df["label"].astype(int)

    return X, y


def prepare_multiclass_dataset(df):
    """
    Prepare dataset for attack-type classification.

    Only attack records are used.
    """

    attack_df = df[df["label"] == 1].copy()

    X = create_features(attack_df)

    y = attack_df["type"].astype(str)

    return X, y


if __name__ == "__main__":

    df = load_data()

    print("\nCreating binary classification features...")

    X_binary, y_binary = prepare_binary_dataset(df)

    print("Binary feature shape:", X_binary.shape)
    print("Binary target shape:", y_binary.shape)

    print("\nCreating multiclass attack features...")

    X_multi, y_multi = prepare_multiclass_dataset(df)

    print("Multiclass feature shape:", X_multi.shape)
    print("Multiclass target shape:", y_multi.shape)

    print("\nFeature columns:")

    for column in X_binary.columns:
        print("-", column)

    print("\nBinary labels:")
    print(y_binary.value_counts())

    print("\nAttack types:")
    print(y_multi.value_counts())