#importing the necessary modules
import numpy as np
import pandas as pd
from pandas import DataFrame as df
from pandas import Series as sr

#initializing the global variables
alphabets=list('abcdefghijklmnopqrstuvwxyz')
a_to_n=dict(zip(alphabets,range(26)))
n_to_a=dict(zip(range(26),alphabets))
#setting the frequency of the english alphabet
freq=[8.497,1.492,2.202,4.253,11.162,2.228,2.015,6.094,7.546,0.153,1.292,4.025,2.406,6.749,7.507,1.929,0.095,7.587,6.327,9.356,2.758,0.978,2.560,0.150,1.994,0.077]
alpha_numeric=' '.join(list(np.array(range(26),dtype=str))+alphabets)
lt=list(range(26))+list(range(26))
a_dict_n=dict(zip(alpha_numeric.split(),lt))


#function to decrypt the cipher using all 26 possible key
def show_all_poss(text):
    global alphabets
    data=text.strip().lower()
    l=list(data)
    x=[]
    for i in range(26):
        s=[]
        for j in range(len(l)):
            s.append(n_to_a[((a_to_n[l[j]])-i)%26])
        x.append(''.join(s))
    xs=sr(x)
    frame=df(xs,index=pd.Index(range(26),name='shift'),columns=pd.Index(['Decoded_Text']))
    frame['Key']=alphabets
    return df(frame,columns=pd.Index(['Key','Decoded_Text'],name='Caesar_cipher'))

#function to find the key
def find_key(text):
    global alphabets,freq
    l=list(text.strip().lower())
    t=sr(l)
    t1=sr(t.value_counts(),index=alphabets).fillna(0)
    t2=t1/t.count()
    sm=0
    shift=0
    for i in range(26):
        f=sr(index=alphabets,dtype='float64')
        for j in range(26):
            f[j]=freq[(j-i)%26]
        s=(f*t2).sum()
        if s>sm:
            sm=s
            shift=i
    return shift

#function to decrypt the cipher using the given key
#if key is not given then a key is found using the 'find_key' function
#if show_all is set to True then cipher is decrypted using all 26 possible key
def decrypt(text,key=None,show_all=False):
    global flag,alphabets,a_to_n,n_to_a,a_dict_n
    if key==None:
        if show_all==False:
            flag=True
            key=find_key(text)
            return decrypt(text,key,False)
        if show_all:
            print('All possible key lengths and corresponding decrypted texts:')
            return show_all_poss(text)
    if key!=None:
        if len(list(str(key)))!=1 and type(key)!=int:
            print('Key length must be 1')
            return
        flag=True
        dcd=[]
        if type(key)==int:
            key=key%26
        k=a_dict_n[str(key)]
        l=list(text.strip().lower())
        for i in range(len(l)):
            x=((a_to_n[l[i]])-k)%26
            dcd.append(n_to_a[x])
        dcd_text=''.join(dcd)
        if show_all:
            f=show_all_poss(text)
            print('Key:'+str(n_to_a[k]))
            print('Decoded Text:',dcd_text)
            print()
            print('Other possible key lengths and decoded text:')
            flag=False
            return f
        print('Key:'+str(n_to_a[k]))
        print('Decoded Text:')
        flag=False
        return dcd_text

#function to encrypt the text using the given key
#if a key is not given then a random key is selected and the text is encrypted using the key
def encrypt(text,key=None):
    global a_to_n,n_to_a,a_dict_n
    l=list(text.strip().lower())
    if key==None:
        key=np.random.randint(26)
        return encrypt(text,key)
    if len(list(str(key)))!=1 and type(key)!=int:
        print('Key length must be 1')
        return
    encd=[]
    if type(key)==int:
        key=key%26
    k=a_dict_n[str(key)]
    for i in range(len(l)):
        x=((a_to_n[l[i]])+k)%26
        encd.append(n_to_a[x])
    encd_text=''.join(encd)
    print('Key:'+str(n_to_a[k]))
    print('Encoded Text:')
    return encd_text
