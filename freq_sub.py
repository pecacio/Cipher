import numpy as np
import pandas as pd
from pandas import DataFrame as df
from pandas import Series as sr
def freq_sub(data):
    data=data.strip()
    data=data.lower()
    x=np.array(list(data))
    l=sr(list(data))
    s=l.value_counts()
    t1=list('etaonrishdlfcmugypwbvkjxzq')
    s1=sr(t1,index=s.index)
    dcdl=[]
    for i in range(len(x)):
        dcdl.append(s1[x[i]])
    dcd=''.join([str(i) for i in dcdl])
    print(dcd)

    
