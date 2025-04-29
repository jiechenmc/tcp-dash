import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

con = sqlite3.connect("good-low.db")
cur = con.cursor()
res = cur.execute("select * from data;")

data = res.fetchall()

# Getting and Cleaning Data

df = pd.DataFrame(data)
df = df.drop(df.columns[0], axis=1)
df.columns = ['name', 'time', 'metric', "metricTime", "metricValue"]
df['time'] = pd.to_datetime(df['time'])
df[['video', 'cc', 'abr', 'http']] = df['name'].str.split(' - ', expand=True)
df = df.drop('name', axis=1)
df["metricValue"] = pd.to_numeric(df["metricValue"], errors="coerce")

# Filter df to include only stallRate and bitrate

df = df[df["metric"].isin(["stallRate", "bitrate"])]
df = df.groupby(["metric", "cc"]).agg({
    "metricValue": "mean",
})


plt.figure(figsize=(12, 6))
ax = df.plot.line()
fig = ax.get_figure()
fig.savefig("out.png")
print(df)