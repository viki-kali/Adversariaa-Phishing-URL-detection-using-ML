#Program starts
import codecs
import decimal
import ipinfo
import ipaddress
import mechanize
from mechanize import Browser                             #version 0.4.7
import urllib.request
import random
import enchant                                            #version 3.2.1
from hyphenate import hyphenate_word                      #version 1.1.0
from ipwhois import IPWhois                               #version 0.11.0
import whois
from reportlab.platypus.tableofcontents import delta      #version 3.4.0
from tld import get_tld                                   #version 0.12.6
import math                                               #version 1.0.1
from collections import Counter
import urllib.parse
import sys                                                #version 0.3
import string
import tldextract                                         #version 3.1.2
import time
from urllib.error import HTTPError, URLError
from datetime import datetime, date                       #version 2.0.2
import subprocess
import re
from nltk.corpus import wordnet
from pronounceable import Complexity                      #version 0.1.3
from selenium import webdriver                            #version 3.141.0
import requests                                           #version 2.25.1
from bs4 import BeautifulSoup                             #version 4.9.3
from requests.exceptions import RequestException
import csv
import pandas as pd                                       #version 1.1.5
from xdg.Locale import regex                              #version 0.25
#from coding import is_registered                          #version 0.5.1
#import homo_dictionary
from urllib.parse import urlparse                         #version 1.22
from googlesearch import search                           #version 1.0.1
import numpy                                              #version 1.19.5
import pings                                              #version 0.0.1
from cymruwhois import Client                             #version 1.6
import whois                                              #version 0.7.3
import socket                                             #version 0.1.5
from warnings import filterwarnings
filterwarnings( action="ignore")
import distutils.spawn
from urllib.request import Request, urlopen


#Following list is defined to check user type mistake keyboards. for check Deep Feature: insertion, replacement

qwerty = {'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
          '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5',
          'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0', 'a': 'qwsz', 's': 'edxzaw',
          'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
          'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'}

qwertz = {'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7',
          '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5',
          'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0', 'a': 'qwsy', 's': 'edxyaw',
          'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
          'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'}

azerty = {'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
          '9': '0oi8', '0': 'po9', 'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5',
          'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m', 'q': 'zswa', 's': 'edxwqz',
          'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm',
          'm': 'lp', 'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'}


keyboards = [qwerty, qwertz, azerty]

homo_dictionary = {}



#Function to calculate the total time taken for the execution of the program
def is_registered(domain):
    try:
        domain_info = whois.whois(domain)
        return bool(domain_info.domain_name)
    except Exception as e:
        return False


def load_letters():
    with codecs.open('homoglyph', 'rU', encoding='utf8') as f:
        for line in f:
            key_value = line.split('\n')[0].split(',')
            homo_dictionary[key_value[0]] = key_value[1].split(' ')


# Function to count numeric characters Feature13

def NumericCharCount(str):
    count = 0

    # Creating a set of numeric characters
    numeric = set("0123456789")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If numeric character is present
        # in set numeric
        if num in numeric:
            count = count + 1

    return count


# Function to count english letters Feature14

def EnglishLetterCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of english letters
    engletter = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If english letter is present
        # in set engletter
        if num in engletter:
            count = count + 1

    return count

# Function to count Special Characters Feature15

def SpecialCharCount(s):
    count = 0
    special_chars = set(string.punctuation)

    for char in s:
        if char in special_chars:
            count += 1

    return count


# Function to count Dots Feature16

def DotCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Dot
    dot = set(".")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If dot character is present
        # in set dot
        if num in dot:
            count = count + 1

    return count

# Function to count Semi-colon Feature17

def SemiColCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Semi-colon
    semicolon = set(";")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If semi-colon character is present
        # in set semicolon
        if num in semicolon:
            count = count + 1

    return count


# Function to count Underscore Feature18

def UnderscoreCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Underscore
    underscore = set("_")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If underscore character is present
        # in set underscore
        if num in underscore:
            count = count + 1

    return count


# Function to count Question Mark Feature19

def QuesMarkCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Question Mark
    quesmark = set("?")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Question Mark character is present
        # in set QuesMark
        if num in quesmark:
            count = count + 1

    return count


# Function to count Hash Character Feature20

def HashCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Hash Character
    hashchar = set("#")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Hash Character is present
        # in set hashchar
        if num in hashchar:
            count = count + 1

    return count

# Function to count Equals to Character Feature21

def EqualCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Equals to Character
    equalchar = set("=")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Equals to Character character is present
        # in set equalchar
        if num in equalchar:
            count = count + 1

    return count


# Function to count Percentage Character Feature22

def PercentCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Percentage Character
    percentchar = set("%")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Percentage Character is present
        # in set percentchar
        if num in percentchar:
            count = count + 1

    return count


# Function to count Ampersand Character Feature23

def AmpersandCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Ampersand Character
    ampersandchar = set("&")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Ampersand Character is present
        # in set ampersandchar
        if num in ampersandchar:
            count = count + 1

    return count


# Function to count Dash Character Feature24

def DashCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Dash Character
    dashchar = set("-")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Dash Character is present
        # in set dashchar
        if num in dashchar:
            count = count + 1

    return count


# Function to count Delimiters Feature25

def DelimiterCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Delimiter Characters
    delim = set("(){}[]<>'\"")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Delimiter Character is present
        # in set delimiter
        if num in delim:
            count = count + 1

    str1 = str.lower()
    # In string, what is the count that <? occurs
    a = str1.count("<?")
    if a != 0:
        count = count-a

    str2 = str.lower()
    # In string, what is the count that ?> occurs
    b = str2.count("?>")
    if b != 0:
        count = count-b

    str3 = str.lower()
    # In string, what is the count that <% occurs
    c = str3.count("<%")
    if c != 0:
        count = count - c

    str4 = str.lower()
    # In string, what is the count that %> occurs
    d = str4.count("%>")
    if d != 0:
        count = count - d

    str5 = str.lower()
    # In string, what is the count that /* occurs
    e = str5.count("/*")

    str6 = str.lower()
    # In string, what is the count that */ occurs
    f = str6.count("*/")

    return count+a+b+c+d+e+f


# Function to count At Character Feature26

def AtCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of At Character
    atchar = set("@")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If At Character is present
        # in set atchar
        if num in atchar:
            count = count + 1

    return count


# Function to count Tilde Character Feature27

def TildeCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of Tilde Character
    tildechar = set("~")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If Tilde Character character is present
        # in set tildechar
        if num in tildechar:
            count = count + 1

    return count


# Function to count Double Slash Feature28

def DoubleSlashCount(str):
    str = str.lower()
    # In string, what is the count that // occurs
    count = str.count("//")
    return count


# Function to calculate ratio of digits to alphabets Feature09

def DigitAlphabetRatio(str):

    digit = NumericCharCount(str)
    alphabet = EnglishLetterCount(str)
    flag = "Undefined"

    if alphabet != 0:
        ratio = digit/alphabet
        return ratio

    else:
        return flag


# Function to calculate ratio of special characters to alphabets Feature10

def SpecialcharAlphabetRatio(str):

    schar = SpecialCharCount(str)
    alphabet = EnglishLetterCount(str)
    flag = "Undefined"

    if alphabet != 0:
        ratio = schar / alphabet
        return ratio

    else:
        return flag


# Function to calculate ratio of uppercase letters to lowercase letters Feature11

def UppercaseLowercaseRatio(str):
    ucase = 0
    uppercase = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    for num in str:
        if num in uppercase:
            ucase = ucase + 1

    lcase = 0
    lowercase = set("abcdefghijklmnopqrstuvwxyz")
    flag = "Undefined"

    for num in str:
        if num in lowercase:
            lcase = lcase + 1

    if lcase != 0:
        ratio = ucase / lcase
        return ratio

    else:
        return flag


# Function to find length of the URL Feature01

def URLLength(str):
    length = len(str)
    #print ("The length of the URL is: ", length)
    return length


# Function to compute entropy of the URL Feature51

def Entropy(data, unit='natural'):
    base = {
        'shannon' : 2.,
        'natural' : math.exp(1),
        'hartley' : 10.
    }

    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    ent = 0

    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])

    return ent

######################################################################################################################################
#Function to check if IP address is used in hostname Feature02
#test_case_1 = "http://example.com" (False)
#test_case_2 = "http://192.168.0.1" (True)

def CheckIPAsHostName(stri):
    parsed_url = urllib.parse.urlparse(stri)
    h = parsed_url.netloc
    try:
        ipaddress.ip_address(h)
        flag = True
    except ValueError:
        flag = False
    return flag

#Function to find the length of the host name Feature37
# maximum length of hostname is 253 characters
def HostNameLength(str):
    parsed_url = urllib.parse.urlparse(str)
    #print(parsed_url.netloc)
    return len(parsed_url.netloc)


#Function to find the length of the path of the URL Feature38

def PathLength(str):
    parsed_url = urllib.parse.urlparse(str)
    #print(parsed_url.path)
    return len(parsed_url.path)


#Function to find the length of the Query of the URL Feature39

def QueryLength(str):
    parsed_url = urllib.parse.urlparse(str)
    #print(parsed_url.query)
    return len(parsed_url.query)



#Function to find if there is https occurs in host name Feature36

def HttpsInHostName(str):
    parsed_url = urllib.parse.urlparse(str)
    hostname = parsed_url.netloc
    #print(hostname)
    hostname = hostname.lower()
    # In string, what is the count that // occurs
    count = 0
    count = hostname.count("https")
    if count == 0:
        #print("Not present")
        return False
    else:
        if count != 0:
            #print("Present")
            return True


# Function to calculate ratio of Domain length to URL length Feature12

def DomainURLRatio(str):
    urllength = len(str)

    parsed_url = urllib.parse.urlparse(str)
    domain = parsed_url.netloc
    domainlength = len(domain)
    flag = "Undefined"

    if urllength != 0:
        ratio = domainlength / urllength
        return ratio

    else:
        return flag

#Function to find TLD of the URL Feature30


def TLD(str):
    try:
        res = get_tld(str, as_object=True)
        a = res.tld
        return a
    except Exception as e:
        return 0


#Function to check if the URL is hashed or not Feature29
#hashed_url_2 = "2ef7bde608ce5404e97d5f042f95f89f1c232871"  # SHA-1 hash
#ot_hashed_url = "http://example.com"

def is_hex(s):
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(s))

def IsHashed(url):
    if len(url) == 32 and is_hex(url):
        return True  # Assuming it's MD5 hash
    elif len(url) == 40 and is_hex(url):
        return True  # Assuming it's SHA-1 hash
    elif len(url) == 64 and is_hex(url):
        return True  # Assuming it's SHA-256 hash
    # Add more conditions if needed for other hash lengths
    else:
        return False

#Function to check if TLD or ccTLD is used in the subdomain of website URL Feature34
#test_case_1 = "http://com.example.com"     (True) otherwise (False)

def TLDInSubdomain(url):
    try:
        extracted_tld = get_tld(url, fix_protocol=True)
        subdomain_info = tldextract.extract(url)
        subdomain = subdomain_info.subdomain
        return extracted_tld in subdomain
    except Exception as e:
        return False


#Function to check if TLD or ccTLD is used in the path of website URL Feature35

def TLDInPath(str):
    try:
        parsed_url = urllib.parse.urlparse(str)
        h = parsed_url.path
        #print(h)
        res = get_tld(str, fix_protocol=True)
        if res in h:
            #print("Yes")
            return True
        else:
            #print("No")
            return False
    except Exception as e:
        return False


#Function to check if https is used in the website URL Feature32

def HttpsInUrl(str):
    res = "https"
    if res in str:
        #print("Yes")
        return True
    else:
        #print("No")
        return False


#Function to find the distance of digit to alphabet Feature31

def DistDigitAlphabet(str):
    r_avg = 0
    letters = sum(c.isalpha() for c in str)
    #print(letters)
    numbers = sum(c.isdigit() for c in str)
    #print(numbers)
    number_ratio = numbers / len(str)
    alphabet_ratio = letters / len(str)
    #print(alphabet_ratio)
    #print(number_ratio)

    if alphabet_ratio != 0:
        r_avg = r_avg + (number_ratio / alphabet_ratio)
    elif alphabet_ratio == 0:
        r_avg = r_avg + 1

    #print(r_avg)
    #x = number_ratio / alphabet_ratio
    #print(x)

    if alphabet_ratio != 0:
        r_distance = r_avg - (number_ratio / alphabet_ratio)
    elif alphabet_ratio == 0:
        r_distance = r_avg - 1

    return r_distance


#Function to check if the domain name is an English word Feature41

def IsDomainEnglishWord(str):
    parsedurl = tldextract.extract(str)
    dom = parsedurl.domain
    #print(dom)

    res = dom.isalpha()
    return res


#Function to check whether the domain name is meaningful Feature42

def IsDomainMeaningful(str):
    dictionary = enchant.Dict("en_US")
    parsedurl = tldextract.extract(str)
    dom = parsedurl.domain
    #print(dom)

    res = dom.isalpha()
    #print(res)

    if res == True:
        res2 = dictionary.check(dom)
        if res2 == True:
            #print("Meaningful")
            return True
        else:
            #print("Not meaningful")
            return False
    else:
        return False


#Function to check whether the domain name is pronounceable Feature43

def IsDomainPronounceable(str):
    dictionary = enchant.Dict("en_US")
    parsedurl = tldextract.extract(str)
    dom = parsedurl.domain
    #print(dom)

    #syn = wordnet.synsets(dom)[0]
    #res = syn.pos()
    #print(res)

    res2 = dictionary.check(dom)
    res3 = dom.isalpha()

    check = 2
    if res3 == True and res2 == True:
        #if res == "n" or res == "v" or res == "a" or res == "r":
            check = 1
    else:
        check = 0

    if check == 1:
        #print("Pronounceable")
        return True
    else:
        #print("Not pronounceable")
        return False


#Function to check whether the domain name is random Feature44

def IsDomainRandom(str):
    dictionary = enchant.Dict("en_US")
    parsedurl = tldextract.extract(str)
    dom = parsedurl.domain
    # print(dom)

    # syn = wordnet.synsets(dom)[0]
    # res = syn.pos()
    # print(res)

    res2 = dictionary.check(dom)
    res3 = dom.isalpha()

    check = 2
    if res3 == True and res2 == True:
        # if res == "n" or res == "v" or res == "a" or res == "r":
        check = 1
    else:
        check = 0

    if check == 1:
        #print("Not Random")
        return False
    else:
        #print("Random")
        return True




#Function to calculate Unigram probability of the URL Feature45

def Unigram(str):
    #print("Hello World")

    concat_total_url = ''
    val_without_tld = (str.rsplit('.', 1))[0]
    #print(val_without_tld)

    concat_total_url = concat_total_url + val_without_tld
    #print(concat_total_url)


    # for calculate distribuation alphabet for Unigram calculation
    len_concat_total_url = len(concat_total_url)
    res = Counter(concat_total_url[idx: idx + 1] for idx in range(len_concat_total_url - 1))
    dict_res = dict(res)
    for c in dict_res:
        if len(c) == 1:
            dict_res[c] = dict_res[c] / len_concat_total_url

    # calculate Unigram probability
    concat_url = val_without_tld
    p_uni_gram = 1
    concat_url = val_without_tld
    # print(dict_res)

    # print(type(dict_res))
    res = 1
    for val in dict_res.values():
        res = res * val

    p_uni_gram = res / len(dict_res)
    return p_uni_gram


#Function to calculate Bigram probability of the URL Feature46

def Bigram(str):
    concat_total_url = ''
    val_without_tld = (str.rsplit('.', 1))[0]
    # print(val_without_tld)

    concat_total_url = concat_total_url + val_without_tld
    # print(concat_total_url)


    # for calculate distribuation alphabet for Bigram calculation
    len_concat_total_url = len(concat_total_url)
    res1 = Counter(concat_total_url[idx: idx + 2] for idx in range(len_concat_total_url - 1))
    dict_res1 = dict(res1)
    for c1 in dict_res1:
        if len(c1) == 2:
            dict_res1[c1] = dict_res1[c1] / len_concat_total_url


    # calculate Bigram probability
    concat_url = val_without_tld
    len_concat_total_url_bigram = len(concat_url)
    res_bigram = Counter(concat_url[idx1: idx1 + 2] for idx1 in range(len_concat_total_url_bigram - 1))
    p_bi_gram = 1
    for u1 in res_bigram:
        if len(u1) == 2:
            p_bi_gram = p_bi_gram * dict_res1[u1]
    p_bi_gram = p_bi_gram * (len(concat_url) / len_concat_total_url * 100)
    decimal.getcontext().prec = 25  # Change 25 to the precision you want.
    p_bi_gram = decimal.Decimal(p_bi_gram) / decimal.Decimal(10)

    return p_bi_gram


#Function to calculate Trigram probability of the URL Feature47

def Trigram(str):
    concat_total_url = ''
    val_without_tld = (str.rsplit('.', 1))[0]
    # print(val_without_tld)

    concat_total_url = concat_total_url + val_without_tld
    # print(concat_total_url)


    # for calculate distribuation alphabet for Trigram calculation
    len_concat_total_url = len(concat_total_url)
    res2 = Counter(concat_total_url[idx: idx + 3] for idx in range(len_concat_total_url - 1))
    dict_res2 = dict(res2)
    for c2 in dict_res2:
        if len(c2) == 3:
            dict_res2[c2] = dict_res2[c2] / len_concat_total_url


    # calculate Trigram probability
    concat_url = val_without_tld
    len_concat_total_url_trigram = len(concat_url)
    res_trigram = Counter(concat_url[idx2: idx2 + 3] for idx2 in range(len_concat_total_url_trigram - 1))
    p_tri_gram = 1
    for u2 in res_trigram:
        if len(u2) == 3:
            p_tri_gram = p_tri_gram * dict_res2[u2]
    p_tri_gram = p_tri_gram * (len(concat_url) / len_concat_total_url * 100)
    decimal.getcontext().prec = 25  # Change 25 to the precision you want.
    p_tri_gram = decimal.Decimal(p_tri_gram) / decimal.Decimal(10)

    return p_tri_gram


#Function to count number of sensitive words in a webpage Feature48

def SensitiveWordCount(url):
    max_retries = 1
    retries = 0

    wanted = ['bank', 'Bank', 'banking', 'architect', 'chemist', 'pharma', 'account', 'credit', 'transfer', 'allow',
              'assure', 'government', 'organisation', 'fund', 'secure', 'confirm', 'Secure', 'Confirm', 'webscr',
              'login', 'Login', 'Log in', 'Log In', 'ebayisapi', 'sign in', 'Sign in', 'Sign In', 'sign up', 'Sign up',
              'Sign Up', 'trust', 'authority', 'offer', 'accept', 'Accept', 'admit', 'allow', 'cookies', 'Cookies',
              'safe', 'browse', 'fix', 'get', 'cash', 'credit', 'buy', 'purchase', 'coin', 'money', 'obtain', 'help',
              'connect', 'drug']

    while retries < max_retries:
        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            page_source = urlopen(req).read()
            print("Page source is downloaded.")
            soup = BeautifulSoup(page_source, 'html.parser')

            count = 0
            for word in wanted:
                freq = soup.get_text().lower().count(word)
                count += freq

            return count

        except HTTPError as e:
            if e.code == 429:
                print(f"Too many requests. Retrying in 5 seconds...")
                #time.sleep(5)  # Wait for 5 seconds before retrying
                retries += 1
            else:
                print(f"HTTP Error {e.code}: {e.reason}")
                return 0  # or handle the error as needed

        except (URLError, ConnectionResetError) as e:
            print(f"Netwoek level error occurred: {e}. Retrying...")
            #time.sleep(2)  # Wait for 2 seconds before retrying
            retries += 1
        except Exception as e:
            return 0
    #print("Max retries reached. Unable to fetch page source.")
    return 0  # or return an appropriate value based on your requirements


# Function to check if the domain name is present in suspicious list Feature49

def InSuspiciousList(url):

    wanted = ['login', 'signin', 'bank', 'account', 'update', 'bonus', 'service', 'ebayisapi', 'token', 'confirm', 'secure', 'verify', 'activate', 'suspend', 'restrict', 'limited', 'urgent', 'alert', 'warning', 'free', 'gift', 'prize', 'offer', 'discount', 'win', 'lottery', 'cash', 'prize', 'reward', 'claim', 'click', 'here', 'now', 'limited', 'time', 'offer', 'expires', 'soon', 'act', 'fast',
'today', 'only', 'you', 'winner', 'congratulations', 'selected', 'eligible', 'claim', 'your', 'prize', 'verify', 'identity', 'update', 'information', 'confirm', 'details', 'personal', 'financial', 'security', 'password', 'username', 'pin', 'social', 'security', 'number', 'credit', 'card', 'debit', 'card', 'bank', 'account', 'routing', 'number', 'wire', 'transfer', 'funds', 'billing', 'address', 'phone', 'number', 'email', 'address', 'date', 'birth', "mother's", 'maiden', 'name', 'download', 'install', 'software', 'app', 'update', 'patch', 'fix', 'security', 'vulnerability', 'bug', 'exploit', 'hack']

    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        soup = BeautifulSoup(page_source, 'html.parser')

        count = 0
        for word in wanted:
            freq = soup.get_text().lower().count(word)
            count += freq

        return count
    except Exception as e:
        return 0

##########################################################################################################################
#check Deep Feature Homoglyph and called in Containment()

def generate_homo_dictionary(url):
    homo_dictionary = {}

    for char in url:
        if char.isalpha():
            homo_dictionary[char] = [char.lower(), char.upper()]  # Include both lowercase and uppercase alternatives
            # You can add more alternatives as needed

    return homo_dictionary

def switch_all_letters(url):
    homo_dictionary = generate_homo_dictionary(url)

    domains = []
    domain = url
    a = []
    j = 0
    result1 = set()

    for ws in range(1, len(domain)):
        for i in range(0, (len(domain) - ws) + 1):
            win = domain[i:i + ws]
            j = 0
            while j < ws:
                c = win[j]
                if c in homo_dictionary:
                    win_copy = win
                    for g in homo_dictionary[c]:
                        win = win[:j] + g + win[j+1:]
                        result1.add(domain[:i] + win + domain[i + ws:])
                        win = win_copy
                j += 1

    result2 = set()
    for domain in result1:
        for ws in range(1, len(domain)):
            for i in range(0, (len(domain) - ws) + 1):
                win = domain[i:i + ws]
                j = 0
                while j < ws:
                    c = win[j]
                    if c in homo_dictionary:
                        win_copy = win
                        for g in homo_dictionary[c]:
                            win = win[:j] + g + win[j+1:]
                            result2.add(domain[:i] + win + domain[i + ws:])
                            win = win_copy
                    j += 1

    return list(result1 | result2)


#check Deep Feature Vowel_swap and called in Containment()

def vowel_swap(domain):
    vowels = 'aeiou'
    result = []

    for i in range(0, len(domain)):
        for vowel in vowels:
            if domain[i] in vowels:
                result.append(domain[:i] + vowel + domain[i+1:])

    return list(set(result))


#check Deep Feature bitsquatting and called in Containment()

def bitsquatting(domain):
    result = []
    masks = [1, 2, 4, 8, 16, 32, 64, 128]

    for i in range(0, len(domain)):
        c = domain[i]
        for j in range(0, len(masks)):
            b = chr(ord(c) ^ masks[j])
            o = ord(b)
            if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                result.append(domain[:i] + b + domain[i+1:])

    return result


#check Deep Feature insertion and called in Containment()

def insertion(domain):
    result = []

    for i in range(1, len(domain)-1):
        for keys in keyboards:
            if domain[i] in keys:
                for c in keys[domain[i]]:
                    result.append(domain[:i] + c + domain[i] + domain[i+1:])
                    result.append(domain[:i] + domain[i] + c + domain[i+1:])

    return list(set(result))


#check Deep Feature omission and called in Containment()

def omission(domain):
    result = []

    for i in range(0, len(domain)):
        result.append(domain[:i] + domain[i+1:])

    return list(set(result))


#check Deep Feature repetition and called in Containment()

def repetition(domain):
    result = []

    for i in range(0, len(domain)):
        if domain[i].isalnum():
            result.append(domain[:i] + domain[i] + domain[i] + domain[i+1:])

    return list(set(result))


#check Deep Feature replacement and called in Containment()

def replacement(domain):
    result = []

    for i in range(0, len(domain)):
        for keys in keyboards:
            if domain[i] in keys:
                for c in keys[domain[i]]:
                    result.append(domain[:i] + c + domain[i+1:])

    return list(set(result))


#check Deep Feature subdomain and called in Containment()

def subdomain(domain):
    result = []

    for i in range(1, len(domain)-1):
        if domain[i] not in ['-', '.'] and domain[i-1] not in ['-', '.']:
            result.append(domain[:i] + '.' + domain[i:])

    return result


#check Deep Feature transpose and called in Containment()

def transposition(domain):
    result = []

    for i in range(0, len(domain)-1):
        if domain[i+1] != domain[i]:
            result.append(domain[:i] + domain[i+1] + domain[i] + domain[i+2:])

    return result


#check Deep Feature addition and called in Containment()

def addition(domain):
    result = []

    for i in range(97, 123):
        result.append(domain + chr(i))

    return result


#Function for the following features : Hyphenstring, Homoglyph, Vowel, Bitsquatting, Insertion, Omission, Repeatition, 
# Replacement, Subdomain, Transposition, Addition String : Feature52, Feature53, Feature54, Feature55,
#  Feature56, Feature57, Feature58, Feature59, Feature60, Feature61, Feature62

def Containment(str):
    val_without_tld = (str.rsplit('.', 1))[0]
    tld = (str.split('.'))[-1]
    hyphen_str = hyphenate_word(val_without_tld)

    if len(hyphen_str) == 0:
        hyphen_str = "No_hyphen"
    else:
        #print(hyphen_str)
        for domain in hyphen_str:
            #print(domain)
            if not is_registered(domain + '.' + tld):
                hyphen_str.remove(domain)
                if len(hyphen_str) != 0:
                    continue
                hyphen_str = "No_hyphen"

    #print(hyphen_str)



    homo_str = switch_all_letters(str)

    if len(homo_str) == 0:
        homo_str = "No_homo_str"
    else:
        for domain in homo_str:
            if not is_registered(domain + '.' + tld):
                homo_str.remove(domain)
                if len(homo_str) == 0:
                    homo_str = "No_homo_str"

    #print(homo_str)



    vowel_result = vowel_swap(val_without_tld)

    if len(vowel_result) == 0:
        vowel_result = "No_vowel_result"
    else:
        for domain in vowel_result:
            if not is_registered(domain + '.' + tld):
                vowel_result.remove(domain)
                if len(vowel_result) == 0:
                    vowel_result = "No_vowel_result"

    #print(vowel_result)



    bitsquatting_result = bitsquatting(val_without_tld)

    if len(bitsquatting_result) == 0:
        bitsquatting_result = "bitsquatting_result"
    else:
        for domain in bitsquatting_result:
            if not is_registered(domain + '.' + tld):
                bitsquatting_result.remove(domain)
                if len(bitsquatting_result) == 0:
                    bitsquatting_result = "bitsquatting_result"

    #print(bitsquatting_result)



    insertion_str = insertion(val_without_tld)

    if len(insertion_str) == 0:
        insertion_str = "No_insertion_str"
    else:
        for domain in insertion_str:
            if not is_registered(domain + '.' + tld):
                insertion_str.remove(domain)
                if len(insertion_str) == 0:
                    insertion_str = "No_insertion_str"

    #print(insertion_str)



    omission_str = omission(val_without_tld)

    if len(omission_str) == 0:
        omission_str = "No_omission_str"
    else:
        for domain in omission_str:
            if not is_registered(domain + '.' + tld):
                omission_str.remove(domain)
                if len(omission_str) == 0:
                    omission_str = "No_omission_str"

    #print(omission_str)



    repetition_str = repetition(val_without_tld)

    if len(repetition_str) == 0:
        repetition_str = "No_repetition_str"
    else:
        for domain in repetition_str:
            if not is_registered(domain + '.' + tld):
                repetition_str.remove(domain)
                if len(repetition_str) == 0:
                    repetition_str = "No_repetition_str"

    #print(repetition_str)



    replacement_str = replacement(val_without_tld)

    if len(replacement_str) == 0:
        replacement_str = "No_replacement_str"
    else:
        for domain in replacement_str:
            if not is_registered(domain + '.' + tld):
                replacement_str.remove(domain)
                if len(replacement_str) == 0:
                    replacement_str = "No_replacement_str"

    #print(replacement_str)



    subdomain_str = subdomain(val_without_tld)

    if len(subdomain_str) == 0:
        subdomain_str = "No_subdomain_str"
    else:
        for domain in subdomain_str:
            if not is_registered(domain + '.' + tld):
                subdomain_str.remove(domain)
                if len(subdomain_str) == 0:
                    subdomain_str = "No_subdomain_str"

    #print(subdomain_str)



    transposition_str = transposition(val_without_tld)

    if len(transposition_str) == 0:
        transposition_str = "No_transposition_str"
    else:
        for domain in transposition_str:
            if not is_registered(domain + '.' + tld):
                transposition_str.remove(domain)
                if len(transposition_str) == 0:
                    transposition_str = "No_transposition_str"

    #print(transposition_str)



    addition_str = addition(val_without_tld)

    if len(addition_str) == 0:
        addition_str = "No_addition_str"
    else:
        for domain in addition_str:
            if not is_registered(domain + '.' + tld):
                addition_str.remove(domain)
                if len(addition_str) == 0:
                    addition_str = "No_addition_str"

    #print(addition_str)
    arr = [hyphen_str, homo_str, vowel_result, bitsquatting_result, insertion_str, omission_str, repetition_str,
           replacement_str, subdomain_str, transposition_str, addition_str]
    return arr



# Calculate Levenshtein Distance

def LevenshteinDistanceDP(token1, token2):
    distances = numpy.zeros((len(token1) + 1, len(token2) + 1))

    for t1 in range(len(token1) + 1):
        distances[t1][0] = t1

    for t2 in range(len(token2) + 1):
        distances[0][t2] = t2

    a = 0
    b = 0
    c = 0

    for t1 in range(1, len(token1) + 1):
        for t2 in range(1, len(token2) + 1):
            if (token1[t1 - 1] == token2[t2 - 1]):
                distances[t1][t2] = distances[t1 - 1][t2 - 1]
            else:
                a = distances[t1][t2 - 1]
                b = distances[t1 - 1][t2]
                c = distances[t1 - 1][t2 - 1]
                if (a <= b and a <= c):
                    distances[t1][t2] = a + 1
                elif (b <= a and b <= c):
                    distances[t1][t2] = b + 1
                else:
                    distances[t1][t2] = c + 1

    return distances[len(token1)][len(token2)]


# Calculate entropy and called in CounterBlock()

def Entropy(s):
    p, lns = Counter(s), float(len(s))

    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())


#Function to check if www is used in url Feature04

def URLWithoutwww(selfa):
    selfa = selfa.lower()
    # In string, what is the count that // occurs
    count = selfa.count("www.")
    if count == 0:
        flag = False
        #print("No www used")
    else:
        flag = True
        #print("www used")
    return flag


#Function to check if ftp:// is used in url Feature05

def FTPUsed(selfa):
    selfa = selfa.lower()
    # In string, what is the count that // occurs
    count = selfa.count("ftp://")
    if count == 0:
        flag = False
        #print("No ftp:// used")
    else:
        flag = True
        #print("ftp:// used")
    return flag


#Function to check if files is used in url Feature07

def FilesInURL(selfa):
    selfa = selfa.lower()
    # In string, what is the count that // occurs
    count = selfa.count("files")
    if count == 0:
        flag = False
        #print("No files used")
    else:
        flag = True
        #print("files used")
    return flag


#Function to check if .js is used in url Feature06

def JSUsed(selfa):
    selfa = selfa.lower()
    # In string, what is the count that // occurs
    count = selfa.count(".js")
    if count == 0:
        flag = False
        #print("No .js used")
    else:
        flag = True
        #print(".js used")
    return flag

#Function to check if .css is used in url Feature08

def CSSUsed(selfa):
    selfa = selfa.lower()
    # In string, what is the count that // occurs
    count = selfa.count("css")
    if count == 0:
        flag = False
        #print("No css used")
    else:
        flag = True
        #print("css used")
    return flag


#Function to find IPAddress Feature64


def IPAddress(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        dom = parsed_url.netloc
        IP_address = socket.gethostbyname(dom)
        obj = IPWhois(IP_address)
        result = obj.lookup_rdap()
        asn_num = result.get('asn')
        asn_country = result.get('asn_country_code')
        asn_cidr = result.get('asn_cidr')
        asn_postal_code = ASNPostalCode(IP_address)
        created_date = result.get('asn_date')
        updated_date = ASNUpdationDate(url)
        arr = [IP_address, asn_num, asn_country, asn_cidr,asn_postal_code,created_date,updated_date]
        return arr

    except Exception as e:
        arr = [0,0,0,0,0,0,0]
        return arr



def ASNPostalCode(ip_address):
    # Replace 'YOUR_API_KEY' with your actual ipinfo API key
    api_key = 'a0b3f5e94b8f77'

    # Construct the URL for the ipinfo API
    url = f'https://ipinfo.io/{ip_address}?token={api_key}'

    try:
        # Make the GET request to the ipinfo API
        response = requests.get(url)
        data = response.json()

        # Check if the request was successful
        if response.status_code == 200:
            return data.get('postal')
        else:
            return 0
    except Exception as e:
        return 0

def ASNUpdationDate(domain_name):
    try:
        # Perform a WHOIS query using the whois package
        domain_info = whois.whois(domain_name)
        update_date = domain_info.updated_date
        if isinstance(update_date, list):
            update_date = update_date[0]

        # Extract only the date portion
        formatted_update_date = update_date.strftime('%Y-%m-%d')
        return formatted_update_date

    except Exception as e:
        return 0

#Function to check if any .exe file is contained in the URL Feature03

def CheckEXE(str):
    res = distutils.spawn.find_executable(str)
    if res == None:
        return False
    else:
        return True


#Function to count number of images in the webpage Feature71

def ImgCount(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code
        soup = BeautifulSoup(response.content, 'html.parser')
        img_count = len(soup.find_all('img'))
        return img_count
    except Exception as e:
        return 0  # Or any other value or action you want to take on error




#Function to count the number of links used in the webpage Feature72

def TotalLinks(url):
    try:
        reqs = requests.get(url)
        reqs.raise_for_status()  # Raise an HTTPError for bad responses
        soup = BeautifulSoup(reqs.text, 'html.parser')

        count = 0
        for link in soup.find_all('a'):
            if link.get('href'):
                count += 1

        return count

    except Exception as e:
        return 0  # Or any other value or action you want to take on error



def TitleCheck(url):
    try:
        # Initialize the browser
        br = mechanize.Browser()
        br.set_handle_robots(False)

        # Set the User-Agent header to mimic a real browser
        br.addheaders = [('User-agent',
                          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36')]

        # Open the URL
        response = br.open(url)

        # Get the title
        title = br.title()

        if title is None or title.strip() == "":
            return True
        else:
            return False

    except Exception as e:
        return False  # Or any other value or action you want to take on error


def CheckMailto(url):
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        page_source = page_source.lower()

        CheckMailtocount = page_source.count(b'mailto')
        CheckMailtocount = CheckMailtocount > 0

        count1 = page_source.count(b'frame')
        count2 = page_source.count(b'iframe')
        CheckFrameTagcount = count1 + count2

        if CheckFrameTagcount == 0:
            CheckFrameTagcount=False
        else:
            CheckFrameTagcount=True

        SourceEvalCountcount = page_source.count(b'eval(')
        SourceEscapeCountcount = page_source.count(b'escape(')
        SourceExecCountcount = page_source.count(b'exec(')
        SourceSearchCountcount = page_source.count(b'search(')
        arr=[CheckMailtocount,CheckFrameTagcount,SourceEvalCountcount,SourceEscapeCountcount,SourceExecCountcount,SourceSearchCountcount]
        return arr

    except Exception as e:
        arr=[False,False,0,0,0,0]
        return arr



def ImageOnlyInForm(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        numimg = len(soup.find_all('img'))

        br = mechanize.Browser()
        br.set_handle_robots(False)
        br.addheaders = [('User-agent',
                          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36')]

        # Introduce a delay here to avoid too many requests in a short period
        #time.sleep(2)

        br.open(url)
        res = br.title()

        if numimg > 0 and not res:
            return True  # Only Images
        else:
            return False  # Text with Images

    except Exception as e:
        return False  # Or any other value or action you want to take on error

#Function to find the age of domain since it is registered Feature89

def DomainAgeInDays(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        dom = parsed_url.netloc

        # Attempt to get the IP address of the domain
        IP_address = socket.gethostbyname(dom)

        # Use IPWhois to get information about the IP address
        obj = IPWhois(IP_address)
        result = obj.lookup_rdap()

        # Get the creation date of the domain
        created_date = result.get('asn_date')

        if created_date is None:
            return 0

        # Convert the creation date to datetime object
        created_year = int(created_date[0:4])
        created_month = int(created_date[5:7])
        created_day = int(created_date[8:10])

        today = date.today()
        d0 = date(created_year, created_month, created_day)
        d1 = date(today.year, today.month, today.day)
        delta = d1 - d0

        return delta.days

    except Exception as e:
        return 0  # Or any other value or action you want to take on error


#Function to check if HTML source code contains a JavaScript command to start a popup Window Feature80


def PopUpWindow(url):
    try:
        # input data is URL with protocol
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        # print(page_source)

        page_source = page_source.lower()
        # In string, what is the count that // occurs
        count1 = page_source.count(b'popup(')
        count2 = page_source.count(b'popupform(')
        count = count1 + count2
        if count == 0:
            # print("No popup command used")
            return False
        else:
            # print("Popup command used")
            return True

    except Exception as e:
        return False  # Or any other value or action you want to take on error


def RightClickDisabled(url):
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        page_source = page_source.lower()
        count1 = page_source.count(b"document.addEventListener('contextmenu',")
        count2 = page_source.count(b"$(\"body\").on(\"contextmenu\".function(e)")
        count3 = page_source.count(b"$(\"img\").bind(\"contextmenu\".function(e)")
        count = count1 + count2 + count3

        if count == 0:
            # print("No command to disable right key")
            return False
        else:
            # print("Disable right key command used")
            return True

    except Exception as e:
        return False  # Or any other value or action you want to take on error

#Function to check if HTML source code contains a JavaScript command on MouseOver to display a fake URL in the 
#status bar Feature78
def FakeLinkInStatusBar(url):
        # input data is url with protocol
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        # print(page_source)

        page_source = page_source.lower()
        # In string, what is the count that // occurs
        count1 = page_source.count(b"onMouseOver=\"window.status=")
        count2 = page_source.count(b"onMouseOut=\"window.status=")
        count3 = page_source.count(b"onmouseover=\"window.status=")
        count4 = page_source.count(b"onmouseout=\"window.status=")
        count = count1 + count2 + count3 + count4
        if count == 0:
            #print("No fake URL in status bar")
            return False
        else:
            #print("Fake URL in status bar")
            return True

    except Exception as e:
        return False  # Or any other value or action you want to take on error

#Function to find total number of query parameters in the URL Feature73

def NumParameters(url):
    parsed_url = urlparse(url)
    query_parameters = urllib.parse.parse_qs(parsed_url.query)
    num_parameters = sum(len(values) for values in query_parameters.values())
    return num_parameters


#Function to find total number of fragments in the URL Feature74

def NumFragments(url):
    parsed_url = urlparse(url)
    fragments = parsed_url.fragment
    if fragments:
        return len(fragments.split(','))
    else:
        return 0

def TagCount(url):
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        page_source = urlopen(req).read()
        BodyTagCount = page_source.count(b"</body>")
        MetaTagCount = page_source.count(b"<meta>")
        DivTagCount = page_source.count(b"</div>")

        arr=[BodyTagCount,MetaTagCount,DivTagCount]
        return arr

    except Exception as e:
        arr=[0,0,0]
        return arr  # Or any other value or action you want to take on error


#Function to check distribution of word based feature Feature40

def DistWordBased(selfa):
    count1 = selfa.count("admin")
    count2 = selfa.count("personal")
    count3 = selfa.count(".bin")
    count4 = selfa.count("update")
    count5 = selfa.count("verification")
    count6 = selfa.count("abuse")
    count7 = selfa.count(".php")

    count = count1 + count2 + count3 + count4 + count5 + count6 + count7
    if count == 0:
        #print("Doubtful words used")
        return True
    else:
        #print("No such word used")
        return False


#Function to check presence of file extention Feature33

def FileExtension(selfa):
    count1 = selfa.count(".zip")
    count2 = selfa.count(".jpg")
    count3 = selfa.count(".gif")
    count4 = selfa.count(".rar")
    count5 = selfa.count("download.php")
    count6 = selfa.count("mail.php")
    count7 = selfa.count(".jar")
    count8 = selfa.count(".swf")
    count9 = selfa.count(".cgi")

    count = count1 + count2 + count3 + count4 + count5 + count6 + count7 + count8 + count9
    if count == 0:
        #print("No such word used")
        return False
    else:
        #print("Such file extension present")
        return True


def GoogleSearchFeature(selfwp):
    try:
        parsed_url = urllib.parse.urlparse(selfwp)
        hostname = parsed_url.netloc

        count = 0
        num = 0
        ld = 0

        query = hostname
        search_results = search(query, num_results=10)

        for j in search_results:
            j = j.lower()
            if hostname in j:
                count += 1
            if num == 0:
                ld = (enchant.utils.levenshtein(j, hostname))

            num += 1

        arr = [ld, count]
        return arr

    except Exception as e:
        arr = [0,0]
        return arr


def domain_name(url):
    return url.split("www.")[-1].split("//")[-1].split(".")[0]

def ensure_http_www_prefix(url):
    if url.startswith("http://www.") or url.startswith("https://www."):
        return url
    elif url.startswith("www."):
        return "http://www." + url[4:]
    elif url.startswith("http://"):
        return "http://www." + url[7:]
    elif url.startswith("https://"):
        return "https://www." + url[8:]
    else:
        return "http://www." + url



#Main Function() starts

if __name__ == "__main__":
    #Read input file from current path
    data = pd.read_csv("mal50.csv", encoding= 'unicode_escape')


    # create pandas data frame to save output
    df = pd.DataFrame(columns=['Sr. No.', 'Domain Name', 'URL Length', 'Is IP as Host name','Is .exe present',
                               'Is www present', 'FTP used', '.js used', 'Files in URL', 'css used',
                               'Digit to alphabet ratio', 'Special Char to Alphabet Ratio',
                               'Uppercase to LowercaseRatio', 'Domain to URL Ratio', 'Numeric Character',
                               'English Letters', 'Special Characters', 'Dots', 'Semicolon', 'Underscore',
                               'Question Mark', 'Hash Character', 'Equals', 'Percentage Character', 'Ampersand', 'Dash',
                               'Delimiters', 'At Character', 'Tilde', 'Double Slash', 'Is Hashed', 'TLD',
                               'Digit to alphabet distance', 'Https in URL', 'File Extention', 'TLD in Subdomain',
                               'TLD in path', 'https in host name', 'Host name length', 'Path length', 'Query length',
                               'Word based distribution', 'Is English word', 'Is Meaningful', 'Is Pronounceable',
                               'Is random', 'Unigram', 'Bigram', 'Trigram', 'Sensitive Words', 'Is domain suspicious',
                               'Levenshtein Distance', 'Entropy', 'Hyphenstring', 'Homoglyph', 'Vowel string',
                               'Bitsquatting', 'Insertion string', 'Omission', 'Repeatition', 'Replacement',
                               'Subdomain', 'Transposition', 'Addition string', 'Google Search Feature', 'IP Address',
                               'ASN Number', 'ASN Country Code', 'ASN CIDR', 'ASN Postal Code', 'ASN creation date',
                               'ASN updation date', 'Total images in webpage', 'Total links', 'Number of parameter',
                               'Number of fragments', 'Body tags in source', 'Meta tag in source', 'Div tag in source',
                               'Fake link in status bar', 'Right click disable', 'Popup window', 'mailto: present',
                               'Frame tag present', 'Is title tag empty', 'Eval() function', 'Escape() function',
                               'Exec() Function', 'Search() function', 'Is image only in webpage', 'Domain Age in Days',
                               'Label'
                               ])

    num = 0
    for index,val in data.iterrows():
        start_time = time.time()
        num = num + 1
        selfwp=ensure_http_www_prefix(val['url'])
        parsed_url = urllib.parse.urlparse(selfwp)
        hostname = parsed_url.netloc
        # Function Call
        R_01 = URLLength(selfwp)
        R_09 = DigitAlphabetRatio(selfwp)
        R_10 = SpecialcharAlphabetRatio(selfwp)
        R_11 = UppercaseLowercaseRatio(selfwp)
        R_12 = DomainURLRatio(selfwp)
        R_13 = NumericCharCount(selfwp)
        R_14 = EnglishLetterCount(selfwp)
        R_15 = SpecialCharCount(selfwp)
        R_16 = DotCount(selfwp)
        R_17 = SemiColCount(selfwp)
        R_18 = UnderscoreCount(selfwp)
        R_19 = QuesMarkCount(selfwp)
        R_20 = HashCharCount(selfwp)
        R_21 = EqualCount(selfwp)
        R_22 = PercentCharCount(selfwp)
        R_23 = AmpersandCount(selfwp)
        R_24 = DashCharCount(selfwp)
        R_25 = DelimiterCount(selfwp)
        R_26 = AtCharCount(selfwp)
        R_27 = TildeCharCount(selfwp)
        R_28 = DoubleSlashCount(selfwp)
        R_51 = Entropy(selfwp)
        R_02 = CheckIPAsHostName(selfwp)
        R_37 = HostNameLength(selfwp)
        R_38 = PathLength(selfwp)
        R_39 = QueryLength(selfwp)
        R_36 = HttpsInHostName(selfwp)
        R_30 = TLD(selfwp)
        R_29 = IsHashed(selfwp)
        R_34 = TLDInSubdomain(selfwp)
        R_35 = TLDInPath(selfwp)
        R_32 = HttpsInUrl(selfwp)
        R_31 = DistDigitAlphabet(selfwp)
        R_41 = IsDomainEnglishWord(selfwp)
        R_42 = IsDomainMeaningful(selfwp)
        R_43 = IsDomainPronounceable(selfwp)
        R_44 = IsDomainRandom(selfwp)
        R_45 = Unigram(selfwp)
        R_46 = Bigram(selfwp)
        R_47 = Trigram(selfwp)
        R_48 = SensitiveWordCount(selfwp)
        R_49 = InSuspiciousList(selfwp)
        R_C = Containment(domain_name(selfwp))
        R_52 = R_C[0]    #hyphen_str
        R_53 = R_C[1]    #homo_str
        R_54 = R_C[2]    #vowel_result
        R_55 = R_C[3]    #bitsquatting_result
        R_56 = R_C[4]    #insertion_str
        R_57 = R_C[5]    #omission_str
        R_58 = R_C[6]    #repetition_str
        R_59 = R_C[7]    #replacement_str
        R_60 = R_C[8]    #subdomain_str
        R_61 = R_C[9]    #transposition_str
        R_62 = R_C[10]   #addition_str
        R_D  = IPAddress(selfwp)
        R_64 = R_D[0]    #ip
        R_65 = R_D[1]    #ASNNumber
        R_66 = R_D[2]    #ASNCountryCode
        R_67 = R_D[3]    #ASNCIDR
        R_68 = R_D[4]    #ASNPostalCode
        R_69 = R_D[5]    #ASNCreationDate
        R_70 = R_D[6]    #ASNUpdationDate
        R_71 = ImgCount(selfwp)
        R_03 = CheckEXE(selfwp)
        R_72 = TotalLinks(selfwp)
        R_83 = TitleCheck(selfwp)
        R_E  = CheckMailto(selfwp)
        R_81 = R_E[0]    #CheckMailto
        R_82 = R_E[1]    #CheckFrameTag
        R_84 = R_E[2]    #SourceEvalCount
        R_85 = R_E[3]    #SourceEscapeCount
        R_86 = R_E[4]    #SourceExecCount
        R_87 = R_E[5]    #SourceSearchCount
        R_88 = ImageOnlyInForm(selfwp)
        R_89 = DomainAgeInDays(selfwp)
        R_80 = PopUpWindow(selfwp)
        R_79 = RightClickDisabled(selfwp)
        R_78 = FakeLinkInStatusBar(selfwp)
        R_73 = NumParameters(selfwp)
        R_74 = NumFragments(selfwp)
        R_F  = TagCount(selfwp)
        R_75 = R_F[0]    #BodyTagCount
        R_76 = R_F[1]    #MetaTagCount
        R_77 = R_F[2]    #DivTagCount
        R_40 = DistWordBased(selfwp)
        R_33 = FileExtension(selfwp)
        R_04 = URLWithoutwww(val['url'])
        R_05 = FTPUsed(val['url'])
        R_06 = JSUsed(val['url'])
        R_07 = FilesInURL(val['url'])
        R_08 = CSSUsed(val['url'])
        R_G = GoogleSearchFeature(selfwp)
        R_50 =R_G[0]
        R_63 =R_G[1]

        # add record to pandas data frame for saving in future
        dic={'Sr. No.': [num],
                        'Domain Name': [hostname],
                        'URL Length': [R_01],
                        'Is IP as Host name': [R_02],
                        'Is .exe present': [R_03],
                        'Is www present': [R_04],
                        'FTP used': [R_05],
                        '.js used': [R_06],
                        'Files in URL': [R_07],
                        'css used': [R_08],
                        'Digit to alphabet ratio':[R_09],
                        'Special Char to Alphabet Ratio': [R_10],
                        'Uppercase to LowercaseRatio': [R_11],
                        'Domain to URL Ratio': [R_12],
                        'Numeric Character': [R_13],
                        'English Letters': [R_14],
                        'Special Characters': [R_15],
                        'Dots': [R_16],
                        'Semicolon': [R_17],
                        'Underscore': [R_18],
                        'Question Mark': [R_19],
                        'Hash Character': [R_20],
                        'Equals': [R_21],
                        'Percentage Character': [R_22],
                        'Ampersand': [R_23],
                        'Dash': [R_24],
                        'Delimiters': [R_25],
                        'At Character': [R_26],
                        'Tilde': [R_27],
                        'Double Slash': [R_28],
                        'Is Hashed': [R_29],
                        'TLD': [R_30],
                        'Digit to alphabet distance': [R_31],
                        'Https in URL': [R_32],
                        'File Extention': [R_33],
                        'TLD in Subdomain': [R_34],
                        'TLD in path': [R_35],
                        'https in host name': [R_36],
                        'Host name length': [R_37],
                        'Path length': [R_38],
                        'Query length': [R_39],
                        'Word based distribution': [R_40],
                        'Is English word': [R_41],
                        'Is Meaningful': [R_42],
                        'Is Pronounceable': [R_43],
                        'Is random': [R_44],
                        'Unigram': [R_45],
                        'Bigram': [R_46],
                        'Trigram': [R_47],
                        'Sensitive Words': [R_48],
                        'Is domain suspicious': [R_49],
                        'Levenshtein Distance': [R_50],
                        'Entropy': [R_51],
                        'Hyphenstring': [R_52],
                        'Homoglyph': [R_53],
                        'Vowel string': [R_54],
                        'Bitsquatting': [R_55],
                        'Insertion string': [R_56],
                        'Omission': [R_57],
                        'Repeatition': [R_58],
                        'Replacement': [R_59],
                        'Subdomain': [R_60],
                        'Transposition': [R_61],
                        'Addition string': [R_62],
                        'Google Search Feature': [R_63],
                        'IP Address': [R_64],
                        'ASN Number': [R_65],
                        'ASN Country Code': [R_66],
                        'ASN CIDR': [R_67],
                        'ASN Postal Code': [R_68],
                        'ASN creation date': [R_69],
                        'ASN updation date': [R_70],
                        'Total images in webpage': [R_71],
                        'Total links': [R_72],
                        'Number of parameter': [R_73],
                        'Number of fragments': [R_74],
                        'Body tags in source': [R_75],
                        'Meta tag in source': [R_76],
                        'Div tag in source': [R_77],
                        'Fake link in status bar': [R_78],
                        'Right click disable': [R_79],
                        'Popup window': [R_80],

                        'mailto: present': [R_81],
                        'Frame tag present': [R_82],
                        'Is title tag empty': [R_83],
                        'Eval() function': [R_84],
                        'Escape() function': [R_85],
                        'Exec() Function': [R_86],
                        'Search() function': [R_87],
                        'Is image only in webpage': [R_88],
                        'Domain Age in Days': [R_89],
                        'Label': [val['label']]}

        dic_df =pd.DataFrame(dic)
        res=pd.concat([df,dic_df],axis=0)
        res.reset_index(drop=True,inplace=True)
        df=res
        end_time = time.time()
        execution_time = round(end_time - start_time)
        print(num,"URLs Completed in",execution_time,"sec, url:",selfwp)

        # save result to output file
        df.to_csv("w1.csv", index=False)


#End of the Program
