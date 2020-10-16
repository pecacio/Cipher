#importing the necessary modules
import numpy as np
import pandas as pd
from pandas import Series as sr
from pandas import DataFrame as df

#initializing the global variables
flag=False
flag2=False
ratio_init=0.6
alphabets=list('abcdefghijklmnopqrstuvwxyz')
a_to_n=dict(zip(alphabets,range(26)))
n_to_a=dict(zip(range(26),alphabets))
freq=[8.497,1.492,2.202,4.253,11.162,2.228,2.015,6.094,7.546,0.153,1.292,4.025,2.406,6.749,7.507,1.929,0.095,7.587,6.327,9.356,2.758,0.978,2.560,0.150,1.994,0.077]

#function to calculate the incidences array in the text to guess the key length 
def incidences(text):
    data=text.strip().lower()
    l=list(data)
    n=len(l)
    incd=[]
    for i in range(n-1):
        s=0
        for j in range(n-1-i):
            if l[j]==l[j+i+1]:
                s=s+1
        incd.append(s)
    return np.array(incd)

#function to compute the possible key lengths from the incidences array
def poss_key_len(text,ratio=ratio_init):
    global ratio_init,flag
    incd=incidences(text)
    ind=[]
    flag1=True
    ctr=0
    while(flag1):
        ctr+=1
        ind=[]
        val=ratio*incd.max()+(1-ratio)*incd.min()
        for i in range(len(incd)):
            if incd[i]>=val:
                ind.append(i)
        ratio=ratio*0.75
        if(len(ind)>1) or ctr>1000:
            flag1=False
    temp=[]
    for i in range(len(ind)-1):
        temp.append(ind[i+1]-ind[i])
    t=sr(temp)
    if len(t)==0:
        print('Cipher Text is too short')
        return 0,[0]
    if flag==False:
        t_dash=sr(t.value_counts(),dtype='float64')
        t_dash.name='frequency'
        t_dash.index.name='keys'
        print(t_dash)
    key_length=t.value_counts().index[0]
    return key_length,list((t.value_counts()).index)

#function to decrypt the cipher using the key length.It is a sub-function of the 'find_key' function
def func(text,key_len):
    global alphabets
    data=text.strip().lower()
    l=list(data)
    n=len(l)
    if key_len>n:
        print('Warning: Key length is greater than length of Cipher Text') 
    l=np.array(l)
    frame=df()
    for i in range(key_len):
        x=l[range(i,len(l),key_len)]
        x1=sr(x)
        x2=sr(x1.value_counts(),index=np.array(alphabets)).fillna(0)
        x3=x2/x1.count()
        frame[i]=x3
    return frame

#function to find the key when the key length is given 
def find_key(text,key_len):
    global alphabets,freq,flag
    frame=func(text,key_len)
    f=sr(freq,index=alphabets)
    shift=[]
    for i in range(key_len):
        t=frame[i]
        sm=0
        shft=0
        for j in range(26):
            f_dash=sr(index=alphabets,dtype='float64')
            for k in range(26):
                f_dash[k]=f[(k-j)%26]
            s=(f_dash*t).sum()
            if s>sm:
                sm=s
                shft=j
        shift.append(shft)
    if flag or flag2:
        return shift
    print('Key: ')
    print(''.join(arrnum_to_arrtext(shift)))
    return shift

#function to decrypt the cipher when key length or the key is given
#if the key or key length is not given then the function 'auto_decrypt' is called
def decrypt(text,key=None,key_len=None):
    global alphabets,a_to_n,n_to_a,flag
    if key==None:
        if key_len==None or key_len<=0:
            return auto_decrypt(text)
        return decrypt(text,find_key(text,key_len),key_len)
    k=np.array(arrtext_to_arrnum(key))
    n=len(k)
    l=list(text.strip().lower())
    dcd=[]
    for i in range(len(l)):
        c=k[i%n]
        t=a_to_n[l[i]]
        d=(t-c)%26
        lttr=n_to_a[d]
        dcd.append(lttr)
    flag=False
    return ''.join(dcd)

#function to decrypt the cipher when key length or key is not given
def auto_decrypt(text,ratio=ratio_init):
    global alphabets,a_to_n,n_to_a,ratio_init,flag
    flag=True
    a,b=poss_key_len(text,ratio)
    key_len=a
    if a==0:
        print('Cannot find key of positive length')
        flag=False
        return
    key=find_key(text,key_len)
    key1=[]
    for i in range(len(key)):
        key1.append(n_to_a[key[i]])
    key_text=(''.join(key1)).upper()
    print('KEY: ',key_text)
    dcd=decrypt(text,key)
    print('\nDECODED TEXT: \n')
    flag=False
    return dcd

#function to encrypt text with a given key
def encrypt(text,key):
    global a_to_n,n_to_a
    keyn=key
    n=len(key)
    if type(key[0])==str:
        keyn=[]
        for i in range(len(key)):
            keyn.append(a_to_n[key[i].lower()])
    l=list(text.strip().lower())
    encd=[]
    for i in range(len(l)):
        c=keyn[i%n]
        t=a_to_n[l[i]]
        d=(t+c)%26
        lttr=n_to_a[d]
        encd.append(lttr)
    print('Encoded Text: \n')
    encd_text=''.join(encd)
    return encd_text

#function to convert the text to numbers
def arrtext_to_arrnum(t):
    global a_to_n
    t1=list(t)
    if type(t1[0])==int:
        return t1
    n1=[]
    for i in range(len(t)):
        n1.append(a_to_n[t1[i]])
    return n1

#function to convert the numbers to text
def arrnum_to_arrtext(n):
    global n_to_a
    n1=list(n)
    t1=[]
    for i in range(len(n)):
        t1.append(n_to_a[n1[i]])
    return t1

#function to decrypt with varying key lengths
#if array of possible key lengths is not given then possible key length array is provided by the ' poss_key_len' function
#if refine is set to True then key_len_array is refined by deleting the key lengths which are multiple of others
def find_key_multiple_keylen(text,key_len_array=None,ratio=ratio_init,refine=False):
    global flag,flag2,ratio_init
    flag=True
    flag2=True
    if key_len_array==None:
        key_len_array=poss_key_len(text,ratio)[1]
        if key_len_array[0]==0:
            print('Cannot find key of positive length')
            return
        if refine==True:
            key_len_array=refinement(key_len_array)
    x=key_len_array
    n=len(x)
    dcd=[]
    for i in range(n):
        key=find_key(text,x[i])
        key_text=arrnum_to_arrtext(key)
        dcd_text=decrypt(text,key)
        dcd.append((key_text,x[i],dcd_text))
    frame=df(dcd,columns=['Key','Key_Len','Decoded text'])
    flag2=False
    return frame

#function to set the letter frequencies of the laguage used 
def set_letter_freq(f=freq):
    global freq
    freq=f
    
#function which removes key lengths which are multiple of others
def refinement(arr):
    a=arr[0]
    x=[a]
    for i in range(1,len(arr)):
        if arr[i]%a!=0:
            x.append(arr[i])
    return x
