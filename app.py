#!/usr/bin/env python
# coding: utf-8

# In[1]:


from flask import Flask, redirect, render_template, request, url_for, session
import time
import re
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract

# Method to count number of dots
def countdots(url):  
    return url.count('.')


# In[13]:


# Method to count number of delimeters
def countdelim(url):
    count = 0
    delim=[';','_','?','=','&']
    for each in url:
        if each in delim:
            count = count + 1
    
    return count


# In[14]:


# Is IP addr present as the hostname, let's validate

import ipaddress as ip #works only in python 3

def isip(url):
    try:
        if ip.ip_address(url):
            return 1
    except:
        return 0


# In[15]:


#method to check the presence of hyphens

def isPresentHyphen(url):
    return url.count('-')


# In[16]:


#method to check the presence of @

def isPresentAt(url):
    return url.count('@')


# In[17]:


def isPresentDSlash(url):
    return url.count('//')


# In[18]:


def countSubDir(url):
    return url.count('/')


# In[19]:


def get_ext(url):
      
    root, ext = splitext(url)
    return ext


# In[20]:


def countSubDomain(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))


# In[21]:


def countQueries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))


# In[22]:


def getFeatures(url, label): 
    result = []
    url = str(url)
    
    #add the url to feature set
    result.append(url)
    
    #parse the URL and extract the domain information
    path = urlparse(url)
    ext = tldextract.extract(url)
    
    #counting number of dots in subdomain    
    result.append(countdots(ext.subdomain))
    
    #checking hyphen in domain   
    result.append(isPresentHyphen(path.netloc))
    
    #length of URL    
    result.append(len(url))
    
    #checking @ in the url    
    result.append(isPresentAt(path.netloc))
    
    #checking presence of double slash    
    result.append(isPresentDSlash(path.path))
    #Count number of subdir    
    result.append(countSubDir(path.path))
    
    #number of sub domain    
    result.append(countSubDomain(ext.subdomain))
    
    #length of domain name    
    result.append(len(path.netloc))
    
    #count number of queries    
    result.append(len(path.query))
    
    #Adding domain information
    
    #if IP address is being used as a URL     
    result.append(isip(ext.domain))
    #result.append(get_ext(path.path))
    result.append(str(label))
    return result

# In[11]:


app = Flask(__name__)
@app.route("/", methods=['GET', 'POST'])
def index():

    if request.method == "GET":
        return render_template("index.html")
    if request.method == 'POST':
        inp = request.form['data']
        if inp == '':
            msg='Sorry..could u please repeat!!!!'
            return render_template("index.html",msg=res)
        else:
            loaded_model = pickle.load(open('phishing3.pkl', 'rb'))
            result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))
            results = getFeatures(inp, '')
            result.loc[0] = results
            result = result.drop(['url','label'],axis=1).values
            result = loaded_model.predict(result)
            res=result[0];
            return render_template("index.html",msg=res)

@app.route("/newlog",methods=["GET","POST"])
def newlog():
	session.clear()
	return redirect(url_for("index"))	

# In[ ]:
if __name__ == '__main__':
    app.run(debug=True)




# In[ ]:







