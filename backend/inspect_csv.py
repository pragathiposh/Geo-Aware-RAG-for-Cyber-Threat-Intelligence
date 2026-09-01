import pandas as pd
from pathlib import Path


csv_path = Path("data/raw/csv/1_otx_threat_intel.csv")

df = pd.read_csv(csv_path)

print("\n========== CSV INFORMATION ==========\n")

print("Number of rows:", len(df))
print("Number of columns:", len(df.columns))

print("\n========== COLUMNS ==========\n")

for column in df.columns:
    print(column)

print("\n========== FIRST 5 ROWS ==========\n")

print(df.head())

print("\n========== DATA TYPES ==========\n")

print(df.dtypes)

print("\n========== MISSING VALUES ==========\n")

print(df.isnull().sum())