import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_db(db_name):
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    res = cur.execute("select * from data;")

    data = res.fetchall()

    # Getting and Cleaning Data

    df = pd.DataFrame(data)
    df = df.drop(df.columns[0], axis=1)
    df.columns = ["name", "time", "metric", "metricTime", "metricValue"]
    df["time"] = pd.to_datetime(df["time"])
    df[["video", "cc", "abr", "http"]] = df["name"].str.split(" - ", expand=True)
    df = df.drop("name", axis=1)
    df["metricValue"] = pd.to_numeric(df["metricValue"], errors="coerce")
    return df


def filter_df(df):
    # Filter df to include only stallRate and bitrate

    df = df[df["metric"].isin(["stallRate", "bitrate"])]
    df["cc"] = df["cc"].apply(lambda x: str(x).split()[0])

    stallrate_df = df[df["metric"] == "stallRate"]
    bitrate_df = df[df["metric"] == "bitrate"]

    # stallrate_df = stallrate_df.groupby(["http", "cc", "abr"]).agg(
    #     {
    #         "metricValue": ["mean", "std"],
    #     }
    # )

    # bitrate_df = bitrate_df.groupby(["http", "cc", "abr"]).agg(
    #     {
    #         "metricValue": ["mean", "std"],
    #     }
    # )

    stallrate_df.to_csv("good-stallRate.csv")
    bitrate_df.to_csv("good-bitrate.csv")

    return stallrate_df, bitrate_df


def plot(df, title, subtitle, xlabel, ylabel, out_filename):
    # print(df)
    df = df.reset_index()
    palette = sns.color_palette("Set2", n_colors=4)

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
        palette=palette,
    )

    g.set_axis_labels(xlabel, ylabel)
    g.set_titles(col_template="{col_name}")

    g.add_legend()

    # g._legend.set_bbox_to_anchor((1.05, 0.5))
    g._legend.set_frame_on(True)
    # plt.tight_layout()
    g.savefig(out_filename, dpi=300, bbox_inches="tight")


def run_flow(db_name, title, subtitle):
    df = load_db(db_name)

    stallrate_df, bitrate_df = filter_df(df)
    xlabel = "Adaptive Bitrate Algorithm (ABR)"

    plot(
        bitrate_df,
        f"{title} Bitrate",
        subtitle,
        xlabel,
        "Mean Bitrate (kbps)",
        f"plots/bitrate-{title}",
    )
    plot(
        stallrate_df,
        f"{title} Stall Rate",
        subtitle,
        xlabel,
        "Mean StallRate (%)",
        f"plots/stallrate-{title}",
    )


run_flow(
    "data/low-1.db",
    "Low Network Condition Trial 1",
    "20ms RTT, No Packet Loss, 10Mbps Bandwidth",
)
run_flow(
    "data/high-1.db",
    "High Network Condition Trial 1",
    "20ms RTT, 1% Packet Loss, 10Mbps Bandwidth",
)
run_flow(
    "data/extreme-1.db",
    "Extreme Network Conditio Trial 1",
    "20ms RTT, 2% Packet Loss, 10Mbps Bandwidth",
)

run_flow(
    "data/low-2.db",
    "Low Network Condition Trial 2",
    "20ms RTT, No Packet Loss, 10Mbps Bandwidth",
)
run_flow(
    "data/high-2.db",
    "High Network Condition Trial 2",
    "20ms RTT, 1% Packet Loss, 10Mbps Bandwidth",
)
run_flow(
    "data/extreme-2.db",
    "Extreme Network Condition Trial 2",
    "20ms RTT, 2% Packet Loss, 10Mbps Bandwidth",
)
