import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns 
import numpy as np

index_bitrate_map = {
    0: "72k",
    1: "76k",
    2: "81k",
    3: "84k",
    4: "166k",
    5: "169k",
    6: "214k",
    7: "320k",
    8: "330k",
    9: "635k",
    10: "732k",
    11: "674k",
    12: "980k",
    13: "1106k",
    14: "1499k",
    15: "2074k",
    16: "1226k",
    17: "1767k",
    18: "2781k",
    19: "2974k",
    20: "4692k",
    21: "3486k",
    22: "4676k",
    23: "8631k",
    24: "6978k",
    25: "13308k",
    26: "18625k"
}
    

def load_db(db_name):
    con = sqlite3.connect(db_name)
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


def filter_df(df, title):
    # Filter df to include only stallRate and bitrate

    times_to_drop = df.loc[(df['metric'] == 'buffer') & (df['metricValue'] < 0.3), 'metricTime'].unique()
    df = df[~df['metricTime'].isin(times_to_drop)]
    df = df[df["metric"].isin(["stallRate", "index"])]
    df = df.dropna()

    # print(df)


    # df = df[df["cc"].isin(["CUBIC","Westwood"])]

#     df["metricValue"] = np.where(
#     df["metric"] == "index",
#     df["metricValue"].astype(int).map(index_bitrate_map),
#     df["metricValue"]
# )

   
    stallrate_df = df[df["metric"] == "stallRate"]
    bitrate_df = df[df["metric"] == "index"]

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
    udp_rows = (
        http3_df.groupby("time", as_index=False)
        .agg({
            "metricValue": "mean",
            "metric": "first",
            "metricTime": "first",
            "video": "first",
            "abr": "first",
            "http": "first"
        })
    )
    udp_rows["cc"] = "UDP"
    df = pd.concat([df, udp_rows], ignore_index=True)
    
    unique_ccs = df["cc"].unique()
    palette = sns.color_palette("Set2", n_colors=len(unique_ccs))
    cc_color_map = dict(zip(unique_ccs, palette))

    # print(cc_color_map)


    # Append the new UDP rows to the original dataframe
    df = df[
        ((df["http"].isin(["HTTP/1.1", "HTTP/2"]))) |
        ((df["http"] == "HTTP/3") & (df["cc"] == "UDP"))
    ]


    

    # t_df = df[(df["cc"] == "Westwood") & (df["abr"] == "Festive")]
    # print(t_df.groupby(["http", "cc", "abr"]).agg({"metricValue": "mean"}))

    #palette = sns.color_palette("Set2", n_colors=5)

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

    
    if "bitrate" in out_filename:
        ticks, _ = plt.yticks()
        labels = [index_bitrate_map.get(int(tick), "") for tick in ticks]
        plt.yticks(ticks, labels)

    g.savefig(out_filename, dpi=300, bbox_inches="tight")
    plt.close()


def run_flow(db_name, title, subtitle):
    df = load_db(db_name)

    stallrate_df, bitrate_df = filter_df(df, title)
    xlabel = "Adaptive Bitrate Algorithm (ABR)"

    print(title)
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


for i in range(1, 6):

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
