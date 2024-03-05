import pandas as pd


def encoding(value):
    if value != '0':
        return 1
    else:
        return 0

d1=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-1.csv")
d2=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-2.csv")
d3=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-3.csv")
d4=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-4.csv")
d5=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-5.csv")
d6=pd.read_csv(r"E:\Project\1-Output\AFTER FEATURE EXTRACTION DATASETS\Feature_Extracted_Dataset-6.csv")

droplist= ['Sr. No.','Domain Name','Hyphenstring','Homoglyph','Vowel string','Bitsquatting','Insertion string','Omission','Repeatition','Replacement','Subdomain','Transposition','Addition string']

d1 = d1.drop(columns=droplist)
d2 = d2.drop(columns=droplist)
d3 = d3.drop(columns=droplist)
d4 = d4.drop(columns=droplist)
d5 = d5.drop(columns=droplist)
d6 = d6.drop(columns=droplist)

d1 = d1.map(lambda x: 1 if x is True else (0 if x is False else x))
d2 = d2.map(lambda x: 1 if x is True else (0 if x is False else x))
d3 = d3.map(lambda x: 1 if x is True else (0 if x is False else x))
d4 = d4.map(lambda x: 1 if x is True else (0 if x is False else x))
d5 = d5.map(lambda x: 1 if x is True else (0 if x is False else x))
d6 = d6.map(lambda x: 1 if x is True else (0 if x is False else x))

d1['TLD'] = d1['TLD'].apply(encoding)
d1['IP Address'] = d1['IP Address'].apply(encoding)
d1['ASN Number'] = d1['ASN Number'].apply(encoding)
d1['ASN Country Code'] = d1['ASN Country Code'].apply(encoding)
d1['ASN CIDR'] = d1['ASN CIDR'].apply(encoding)
d1['ASN Postal Code'] = d1['ASN Postal Code'].apply(encoding)
d1['ASN creation date'] = d1['ASN creation date'].apply(encoding)
d1['ASN updation date'] = d1['ASN updation date'].apply(encoding)

d2['TLD'] = d2['TLD'].apply(encoding)
d2['IP Address'] = d2['IP Address'].apply(encoding)
d2['ASN Number'] = d2['ASN Number'].apply(encoding)
d2['ASN Country Code'] = d2['ASN Country Code'].apply(encoding)
d2['ASN CIDR'] = d2['ASN CIDR'].apply(encoding)
d2['ASN Postal Code'] = d2['ASN Postal Code'].apply(encoding)
d2['ASN creation date'] = d2['ASN creation date'].apply(encoding)
d2['ASN updation date'] = d2['ASN updation date'].apply(encoding)

d3['TLD'] = d3['TLD'].apply(encoding)
d3['IP Address'] = d3['IP Address'].apply(encoding)
d3['ASN Number'] = d3['ASN Number'].apply(encoding)
d3['ASN Country Code'] = d3['ASN Country Code'].apply(encoding)
d3['ASN CIDR'] = d3['ASN CIDR'].apply(encoding)
d3['ASN Postal Code'] = d3['ASN Postal Code'].apply(encoding)
d3['ASN creation date'] = d3['ASN creation date'].apply(encoding)
d3['ASN updation date'] = d3['ASN updation date'].apply(encoding)

d4['TLD'] = d4['TLD'].apply(encoding)
d4['IP Address'] = d4['IP Address'].apply(encoding)
d4['ASN Number'] = d4['ASN Number'].apply(encoding)
d4['ASN Country Code'] = d4['ASN Country Code'].apply(encoding)
d4['ASN CIDR'] = d4['ASN CIDR'].apply(encoding)
d4['ASN Postal Code'] = d4['ASN Postal Code'].apply(encoding)
d4['ASN creation date'] = d4['ASN creation date'].apply(encoding)
d4['ASN updation date'] = d4['ASN updation date'].apply(encoding)

d5['TLD'] = d5['TLD'].apply(encoding)
d5['IP Address'] = d5['IP Address'].apply(encoding)
d5['ASN Number'] = d5['ASN Number'].apply(encoding)
d5['ASN Country Code'] = d5['ASN Country Code'].apply(encoding)
d5['ASN CIDR'] = d5['ASN CIDR'].apply(encoding)
d5['ASN Postal Code'] = d5['ASN Postal Code'].apply(encoding)
d5['ASN creation date'] = d5['ASN creation date'].apply(encoding)
d5['ASN updation date'] = d5['ASN updation date'].apply(encoding)

d6['TLD'] = d6['TLD'].apply(encoding)
d6['IP Address'] = d6['IP Address'].apply(encoding)
d6['ASN Number'] = d6['ASN Number'].apply(encoding)
d6['ASN Country Code'] = d6['ASN Country Code'].apply(encoding)
d6['ASN CIDR'] = d6['ASN CIDR'].apply(encoding)
d6['ASN Postal Code'] = d6['ASN Postal Code'].apply(encoding)
d6['ASN creation date'] = d6['ASN creation date'].apply(encoding)
d6['ASN updation date'] = d6['ASN updation date'].apply(encoding)

common_list =['Levenshtein Distance', 'Body tags in source', 'Number of parameter', 'Digit to alphabet ratio', 'Entropy', 'IP Address', 'Host name length', 'Percentage Character', 'Special Characters', 'Total links', 'Word based distribution', 'Is www present', 'Question Mark', 'Numeric Character', 'At Character', 'Frame tag present', 'Domain to URL Ratio', 'Is domain suspicious', 'Google Search Feature', 'Https in URL', 'Is English word', 'Dots', 'ASN updation date', 'mailto: present', 'Dash', 'Label']

d1 = d1[common_list]
d2 = d2[common_list]
d3 = d3[common_list]
d4 = d4[common_list]
d5 = d5[common_list]
d6 = d6[common_list]

d1.to_csv("Best_25_Features_Dataset-1.csv",index=False)
d2.to_csv("Best_25_Features_Dataset-2.csv",index=False)
d3.to_csv("Best_25_Features_Dataset-3.csv",index=False)
d4.to_csv("Best_25_Features_Dataset-4.csv",index=False)
d5.to_csv("Best_25_Features_Dataset-5.csv",index=False)
d6.to_csv("Best_25_Features_Dataset-6.csv",index=False)
