import pandas as pd

df1=pd.read_csv("Feature_Extracted_Dataset-1.csv")
df2=pd.read_csv("Feature_Extracted_Dataset-2.csv")
df3=pd.read_csv("Feature_Extracted_Dataset-3.csv")
df4=pd.read_csv("Feature_Extracted_Dataset-4.csv")
df5=pd.read_csv("Feature_Extracted_Dataset-5.csv")
df6=pd.read_csv("Feature_Extracted_Dataset-6.csv")

print(df1.describe)
print(df2.describe)
print(df3.describe)
print(df4.describe)
print(df5.describe)
print(df6.describe)
