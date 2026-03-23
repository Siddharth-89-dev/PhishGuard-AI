import pandas as pd

df = pd.read_csv("raw_data.csv")

print(df.head())
print(df.columns)
print(df['label'].value_counts())  # change 'label' if needed