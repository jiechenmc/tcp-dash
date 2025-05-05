import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import sys

index_bitrate_map = {
    1: 72,
    2: 76,
    3: 81,
    4: 84,
    5: 166,
    6: 169,
    7: 214,
    8: 320,
    9: 330,
    10: 635,
    11: 732,
    12: 674,
    13: 980,
    14: 1106,
    15: 1499,
    16: 2074,
    17: 1226,
    18: 1767,
    19: 2781,
    20: 2974,
    21: 4692,
    22: 3486,
    23: 4676,
    24: 8631,
    25: 6978,
    26: 13308,
    27: 18625,
}


def load_db(db_name):
    with sqlite3.connect(db_name) as con:
        cur = con.cursor()
        res = cur.execute("select * from data;")

        data = res.fetchall()

    # Getting and Cleaning Data

    df = pd.DataFrame(data)
    df = df.drop(df.columns[0], axis=1)
    df.columns = ["name", "time", "metric", "metricTime", "metricValue"]
    df["time"] = pd.to_datetime(df["time"], format="%m/%d/%Y, %I:%M:%S %p")
    df[["video", "cc", "abr", "http"]] = df["name"].str.split(" - ", expand=True)
    df["cc"] = df["cc"].apply(lambda x: str(x).split()[0])
    df = df.drop("name", axis=1)
    df["metricValue"] = pd.to_numeric(df["metricValue"], errors="coerce")

    return df


def filter_df(df):
    # Filter df to include only stallRate and bitrate

    times_to_drop = df.loc[
        (df["metric"] == "buffer") & (df["metricValue"] < 0.3), "metricTime"
    ].unique()
    df = df[~df["metricTime"].isin(times_to_drop)]
    df = df[df["metric"].isin(["stallRate", "index"])]
    df = df.dropna()

    return df


def split_df(df, title=None):
    df = filter_df(df)
    stallrate_df = df[df["metric"] == "stallRate"]
    bitrate_df = df[df["metric"] == "index"].copy()

    bitrate_df["metricValue"] = np.floor(bitrate_df["metricValue"]).astype(float)
    bitrate_df["metricValue"] = bitrate_df["metricValue"].map(index_bitrate_map)

    bitrate_df.to_csv(f"data/sheets/{title}.csv", index=False)
    # print(bitrate_df)

    # Map index to actual bitrate
    # bitrate_order = [index_bitrate_map[i] for i in sorted(index_bitrate_map.keys())]
    # bitrate_df['metricValue'] = pd.Categorical(bitrate_df['metricValue'], categories=bitrate_order, ordered=True)

    # Uncomment this to see source data
    # stallrate_df.to_csv(f"data/stallRate-{title}.csv")
    # bitrate_df.to_csv(f"data/bitrate-{title}.csv")

    return stallrate_df, bitrate_df


def plot(df, title, subtitle, xlabel, ylabel, out_filename):
    df = df.reset_index()

    # Filter for HTTP/3 rows
    http3_df = df[df["http"] == "HTTP/3"]

    # Aggregate by 'time'
    udp_rows = http3_df.groupby("time", as_index=False).agg(
        {
            "metricValue": "mean",
            "metric": "first",
            "metricTime": "first",
            "video": "first",
            "abr": "first",
            "http": "first",
        }
    )
    udp_rows["cc"] = "UDP"
    df = pd.concat([df, udp_rows], ignore_index=True)

    unique_ccs = df["cc"].unique()
    palette = sns.color_palette("Set2", n_colors=len(unique_ccs))
    cc_color_map = dict(zip(unique_ccs, palette))

    # print(cc_color_map)

    # Append the new UDP rows to the original dataframe
    df = df[
        (df["http"].isin(["HTTP/1.1", "HTTP/2"]))
        | ((df["http"] == "HTTP/3") & (df["cc"] == "UDP"))
    ]

    # t_df = df[(df["cc"] == "Westwood") & (df["abr"] == "Festive")]
    # print(t_df.groupby(["http", "cc", "abr"]).agg({"metricValue": "mean"}))

    # palette = sns.color_palette("Set2", n_colors=5)

    g = sns.FacetGrid(df, col="http", height=4, aspect=1.2)
    g.figure.set_size_inches(12, 4)
    g.figure.suptitle(title, fontsize=16, y=1.05)
    g.figure.text(
        0.5,
        0.95,
        subtitle,
        ha="center",
        fontsize=12,
        style="italic",
    )

    g.map_dataframe(
        sns.barplot,
        x="abr",
        y="metricValue",
        hue="cc",
        estimator="mean",
        palette=cc_color_map,
    )

    g.set_axis_labels(xlabel, ylabel)
    g.set_titles(col_template="{col_name}")

    g.add_legend()

    # g._legend.set_bbox_to_anchor((1.05, 0.5))
    g._legend.set_frame_on(True)

    # if "bitrate" in out_filename:
    # ticks, _ = plt.yticks()
    # labels = [index_bitrate_map.get(int(tick), "") for tick in ticks]
    # plt.yticks(ticks, labels)

    g.savefig(out_filename, dpi=300, bbox_inches="tight")
    plt.close()


def run_flow(db_name, title, subtitle):
    df = load_db(db_name)

    stallrate_df, bitrate_df = split_df(df, title)
    xlabel = "Adaptive Bitrate Algorithm (ABR)"

    # print(title)
    plot(
        bitrate_df,
        f"{title} Bitrate",
        subtitle,
        xlabel,
        "Mean Bitrate (kbps)",
        f"plots/trial/bitrate-{title}",
    )
    plot(
        stallrate_df,
        f"{title} Stall Rate",
        subtitle,
        xlabel,
        "Mean Stall Rate (%)",
        f"plots/trial/stallrate-{title}",
    )


def sub_plot_bitrate(bitrate_df, title, subtitle):
    plot(
        bitrate_df,
        f"{title} Bitrate",
        subtitle,
        "Adaptive Bitrate Algorithm (ABR)",
        "Mean Bitrate (kbps)",
        f"plots/bitrate-{title}",
    )


def sub_plot_stall(stallrate_df, title, subtitle):
    plot(
        stallrate_df,
        f"{title} Stall Rate",
        subtitle,
        "Adaptive Bitrate Algorithm (ABR)",
        "Mean Stall Rate (%)",
        f"plots/stall-{title}",
    )


def validate_df(df):
    counts = df.groupby(["cc", "abr"])["http"].nunique()
    return (counts == 3).all()


def plot_all(num_of_trials):
    lstall_arr, hstall_arr, estall_arr = [], [], []
    lbit_arr, hbit_arr, ebit_arr = [], [], []

    for i in range(1, num_of_trials + 1):
        lstall, lbit = split_df(load_db(f"data/low-{i}.db"))
        hstall, hbit = split_df(load_db(f"data/high-{i}.db"))
        estall, ebit = split_df(load_db(f"data/extreme-{i}.db"))

        if validate_df(lstall):
            lstall_arr.append(lstall)
        else:
            counts = lstall.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"Low Network Trial {i} Stall Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)

        if validate_df(hstall):
            hstall_arr.append(hstall)
        else:
            counts = hstall.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"High Network Trial {i} Stall Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)
        if validate_df(estall):
            estall_arr.append(estall)
        else:
            counts = estall.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"Extreme Network Trial {i} Stall Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)
        if validate_df(lbit):
            lbit_arr.append(lbit)
        else:
            counts = lbit.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"Low Network Trial {i} Bitrate Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)
        if validate_df(hbit):
            hbit_arr.append(hbit)
        else:
            counts = hbit.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"High Network Trial {i} Bitrate Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)
        if validate_df(ebit):
            ebit_arr.append(ebit)
        else:
            counts = ebit.groupby(["cc", "abr"])["http"].nunique()
            print(
                f"Extreme Network Trial {i} Bitrate Data Missing\n{counts[counts != 3]}",
                file=sys.stderr,
            )
            print(file=sys.stderr)

    low_stall_df = pd.concat(lstall_arr)
    high_stall_df = pd.concat(hstall_arr)
    extreme_stall_df = pd.concat(estall_arr)

    low_bit_df = pd.concat(lbit_arr)
    high_bit_df = pd.concat(hbit_arr)
    extreme_bit_df = pd.concat(ebit_arr)

    low_bit_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/low-bitrate-summary.csv")

    high_bit_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/high-bitrate-summary.csv")
    extreme_bit_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/extreme-bitrate-summary.csv")

    low_stall_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/low-stallrate-summary.csv")
    high_stall_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/high-stallrate-summary.csv")
    extreme_stall_df.groupby(["http", "cc", "abr"])["metricValue"].mean(
        numeric_only=True
    ).to_csv("data/sheets/extreme-stallrate-summary.csv")

    # print(low_bit_df)

    sub_plot_bitrate(
        low_bit_df,
        "Low Network Condition Summary",
        "20ms RTT, No Packet Loss, 10Mbps Bandwidth",
    )

    sub_plot_bitrate(
        high_bit_df,
        "High Network Condition Summary",
        "100ms RTT, 1% Packet Loss, 10Mbps Bandwidth",
    )

    sub_plot_bitrate(
        extreme_bit_df,
        "Extreme Network Condition Summary",
        "200ms RTT, 2% Packet Loss, 10Mbps Bandwidth",
    )

    sub_plot_stall(
        low_stall_df,
        "Low Network Condition Summary",
        "20ms RTT, No Packet Loss, 10Mbps Bandwidth",
    )

    sub_plot_stall(
        high_stall_df,
        "High Network Condition Summary",
        "100ms RTT, 1% Packet Loss, 10Mbps Bandwidth",
    )

    sub_plot_stall(
        extreme_stall_df,
        "Extreme Network Condition Summary",
        "200ms RTT, 2% Packet Loss, 10Mbps Bandwidth",
    )


def plot_trial(num_of_trials):
    for i in range(1, num_of_trials + 1):
        run_flow(
            f"data/low-{i}.db",
            f"Low Network Condition Trial {i}",
            "20ms RTT, No Packet Loss, 10Mbps Bandwidth",
        )
        run_flow(
            f"data/high-{i}.db",
            f"High Network Condition Trial {i}",
            "20ms RTT, 1% Packet Loss, 10Mbps Bandwidth",
        )
        run_flow(
            f"data/extreme-{i}.db",
            f"Extreme Network Condition Trial {i}",
            "20ms RTT, 2% Packet Loss, 10Mbps Bandwidth",
        )


if __name__ == "__main__":
    num_of_trials = 6
    plot_all(num_of_trials)  # Plot all is Kinda buggy right now
    plot_trial(num_of_trials)
