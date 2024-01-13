import pandas as pd

path1="./Dataset/Good/1-Alexa.csv"
path2="./Dataset/Good/2-crowd flower.csv"
path3="./Dataset/Good/3-DMOZ.csv"
path4="./Dataset/Good/4-Benign.csv"
path5="./Dataset/Good/5-Non Malicious.csv"
path6="./Dataset/ISCXURL2016/URL/Benign_list_big_final.csv"
path7="./Dataset/Malicious/1-Phishing site url.csv"
path8="./Dataset/Malicious/2-Phishtank.csv"
path9="./Dataset/Malicious/3-Malicious data url.csv"
path10="./Dataset/ISCXURL2016/URL/phishing_dataset.csv"
path11="./Dataset/Malicious/5-Phishstorm.csv"
path12="./Dataset/Malicious/6-Malicious set.csv"


column_names1 = ['index', 'url']
dataset1 = pd.read_csv(path1, encoding="ascii",names=column_names1)

dataset2 = pd.read_csv(path2, encoding="ascii", low_memory=False)

column_names3 = ['index', 'url','type']
dataset3 = pd.read_csv(path3, encoding="utf-8",names=column_names3)

column_names4 = ['index','url','label','result']
dataset4 = pd.read_csv(path4, encoding="utf-8",low_memory=False,names=column_names4)
dataset4 = dataset4[dataset4['label'] == 'benign']

column_names5 = ['url', 'ranking', 'mld_res', 'mld.ps_res', 'card_rem', 'ratio_Rrem', 'ratio_Arem', 'jaccard_RR', 'jaccard_RA', 'jaccard_AR', 'jaccard_AA','jaccard_ARrd', 'jaccard_ARrem', 'label']
dataset5 = pd.read_csv(path5, encoding="MacRoman", on_bad_lines='skip',low_memory=False,names=column_names5)
dataset5 = dataset5[dataset5['label'] != 1.0]

column_names6 = ['url']
dataset6 = pd.read_csv(path6, encoding="ascii", names=column_names6)

column_names7=['url', 'label']
dataset7 =  pd.read_csv(path7, encoding="MacRoman", names=column_names7)
dataset7 = dataset7[dataset7['label'] == 'bad']

dataset8 =  pd.read_csv(path8, encoding="utf-8", low_memory=False)
dataset9 =  pd.read_csv(path9, encoding="utf-8")
dataset9 = dataset9[dataset9['label'] == 'bad']

column_names10 = ['url']
dataset10 = pd.read_csv(path10, encoding="utf-8", names=column_names10)

column_names11 =['url', 'ranking', 'mld_res', 'mld.ps_res', 'card_rem', 'ratio_Rrem',
        'ratio_Arem', 'jaccard_RR', 'jaccard_RA', 'jaccard_AR', 'jaccard_AA',
       'jaccard_ARrd', 'jaccard_ARrem', 'label']
dataset11 = pd.read_csv(path11, encoding="MacRoman", on_bad_lines='skip',low_memory=False, names=column_names11)
dataset11 = dataset11[dataset11['label'] == '1.0']

dataset12 = pd.read_csv(path12, encoding="utf-8")

#Extract 'url' feature from all the datasets
dataset1 =pd.DataFrame(dataset1['url'])
dataset2 =pd.DataFrame(dataset2['url'])
dataset3 =pd.DataFrame(dataset3['url'])
dataset4 =pd.DataFrame(dataset4['url'])
dataset5 =pd.DataFrame(dataset5['url'])
dataset6 =pd.DataFrame(dataset6['url'])
dataset7 =pd.DataFrame(dataset7['url'])
dataset8 =pd.DataFrame(dataset8['url'])
dataset9 =pd.DataFrame(dataset9['url'])
dataset10=pd.DataFrame(dataset10['url'])
dataset11=pd.DataFrame(dataset11['url'])
dataset12=pd.DataFrame(dataset12['url'])

min_rows=500

#label-0 => Good Urls
#label-1 => Malicious Urls

dataset1_sampled = dataset1.sample(n=min_rows, random_state=42)
dataset1_sampled['label']=0
dataset7_sampled = dataset7.sample(n=min_rows, random_state=42)
dataset7_sampled['label']=1
result_dataset1 = pd.concat([dataset1_sampled, dataset7_sampled], axis=0)
result_dataset1.reset_index(drop=True, inplace=True)

dataset2_sampled = dataset2.sample(n=min_rows, random_state=42)
dataset2_sampled['label']=0
dataset8_sampled = dataset8.sample(n=min_rows, random_state=42)
dataset8_sampled['label']=1
result_dataset2 = pd.concat([dataset2_sampled, dataset8_sampled], axis=0)
result_dataset2.reset_index(drop=True, inplace=True)

dataset3_sampled = dataset3.sample(n=min_rows, random_state=42)
dataset3_sampled['label']=0
dataset9_sampled = dataset9.sample(n=min_rows, random_state=42)
dataset9_sampled['label']=1
result_dataset3 = pd.concat([dataset3_sampled, dataset9_sampled], axis=0)
result_dataset3.reset_index(drop=True, inplace=True)

dataset4_sampled = dataset4.sample(n=min_rows, random_state=42)
dataset4_sampled['label']=0
dataset10_sampled = dataset10.sample(n=min_rows, random_state=42)
dataset10_sampled['label']=1
result_dataset4 = pd.concat([dataset4_sampled, dataset10_sampled], axis=0)
result_dataset4.reset_index(drop=True, inplace=True)

dataset5_sampled = dataset5.sample(n=min_rows, random_state=42)
dataset5_sampled['label']=0
dataset11_sampled = dataset11.sample(n=min_rows, random_state=42)
dataset11_sampled['label']=1
result_dataset5 = pd.concat([dataset5_sampled, dataset11_sampled], axis=0)
result_dataset5.reset_index(drop=True, inplace=True)

dataset6_sampled = dataset6.sample(n=min_rows, random_state=42)
dataset6_sampled['label']=0
dataset12_sampled = dataset12.sample(n=min_rows, random_state=42)
dataset12_sampled['label']=1
result_dataset6 = pd.concat([dataset6_sampled, dataset12_sampled], axis=0)
result_dataset6.reset_index(drop=True, inplace=True)

#This will generate six datasets, containing both good and malicious url in equal ratio
result_dataset1.to_csv("(url,label)copy_0f_combined_dataset1.csv", index=False)
result_dataset2.to_csv("(url,label)copy_0f_combined_dataset2.csv", index=False)
result_dataset3.to_csv("(url,label)copy_0f_combined_dataset3.csv", index=False)
result_dataset4.to_csv("(url,label)copy_0f_combined_dataset4.csv", index=False)
result_dataset5.to_csv("(url,label)copy_0f_combined_dataset5.csv", index=False)
result_dataset6.to_csv("(url,label)copy_0f_combined_dataset6.csv", index=False)
