#!/usr/bin/env python
# coding: utf-8

# # Importing the required packages

# In[2]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.utils import resample
import seaborn as sns
from urllib.parse import urlparse
import tldextract
from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.metrics import confusion_matrix,classification_report
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
from sklearn.model_selection import learning_curve


# # Loading the Train Dataset

# In[3]:


df=pd.read_csv("url train dataset.csv",delimiter = ',',encoding = 'unicode_escape', low_memory = False)


# In[4]:


df.head()


# In[5]:


df.info()


# In[6]:


df.describe()


# # Checking dataset distribution

# In[7]:


df['label'].value_counts()


# # Plot of unbalanced distribution

# In[8]:


df_ublabel0 = df[df.label==0]
df_ublabel1 = df[df.label==1]
df_ubclass = pd.concat([df_ublabel0,df_ublabel1]) 


# In[9]:


plt.figure(figsize=(5, 8))
sns.countplot('label', data=df_ubclass)
plt.title('unbalanced Classes')
plt.show()


# # Resampling and balancing dataset

# In[10]:


df_blabel1_resampled = resample(df_ublabel1, replace= False, n_samples=6251)
df_bsampled = pd.concat([df_blabel1_resampled,df_ublabel0]) 
df_bsampled.label.value_counts()                                


# In[11]:


plt.figure(figsize=(5,8))
sns.countplot('label', data=df_bsampled)
plt.title('Balanced Classes')
plt.show()


# # Creating Features from train data

# In[12]:


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


featureSet = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))


# In[23]:


#get_ipython().system('pip install tldextract')


# In[24]:



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


# In[25]:


for i in range(len(df)):
    features = getFeatures(df["domain"].loc[i],df["label"].loc[i])    
    featureSet.loc[i] = features


# In[37]:


featureSet.head()


# In[38]:


featureSet.info()


# # Visualizing of Features
# 

# In[39]:


sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['len of url'],color='green',label='Benign')
sns.distplot(featureSet[featureSet['label']=='1']['len of url'],color='red',label='Phishing')
plt.title('Distribution of URL Length')
plt.legend(loc='upper right')
plt.xlabel('Length of URL')
plt.show()


# In[40]:


sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['no of dots'],color='green',label='Benign')
sns.distplot(featureSet[featureSet['label']=='1']['no of dots'],color='red',label='Phishing')
plt.title('Distribution of Dots')
plt.legend(loc='upper right')
plt.xlabel('No of Dots')
plt.show()


# In[41]:


sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['no of subdir'],color='green',label='Benign')
sns.distplot(featureSet[featureSet['label']=='1']['no of subdir'],color='red',label='Phishing')
plt.title('Distribution of Subdirectory')
plt.legend(loc='upper right')
plt.xlabel('No of Subdirectory')
plt.show()


# In[42]:


sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['no of subdomain'],color='green',label='Benign')
sns.distplot(featureSet[featureSet['label']=='1']['no of subdomain'],color='red',label='Phishing')
plt.title('Distribution of Subdomain')
plt.legend(loc='upper right')
plt.xlabel('No of Subdomains')
plt.show()


# In[43]:


sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['no of queries'],color='green',label='Benign')
sns.distplot(featureSet[featureSet['label']=='1']['no of queries'],color='red',label='Phishing')
plt.title('Distribution of Queries')
plt.legend(loc='upper right')
plt.xlabel('No of Queries')
plt.show()


# # Splitting the dataset to test and train

# In[44]:


X=featureSet.iloc[:,1:11].values
Y=featureSet.iloc[:,11].values
X_train,X_test,Y_train,Y_test=train_test_split(X,Y,test_size=0.2,random_state=0)


# In[45]:


print(X_train.shape)
print(Y_train.shape)


# In[46]:


print(X_test.shape)
print(Y_test.shape)


# # Training classifiers and testing without hyper parameter tuning

# In[47]:


print('Decision Tree Classifier')
clf1 = tree.DecisionTreeClassifier()
clf1.fit(X_train,Y_train)
Y_pred = clf1.predict(X_test)
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))


# In[52]:


print('Adaboost Classifier')
clf2 = AdaBoostClassifier()
clf2.fit(X_train,Y_train)
Y_pred = clf2.predict(X_test)
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))


# In[53]:


print('Logistic Regression Classifier')
clf3 = LogisticRegression()
clf3.fit(X_train,Y_train)
Y_pred = clf3.predict(X_test)
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))


# In[54]:


print('Gaussian NB Classifier')
clf4 = GaussianNB()
clf4.fit(X_train,Y_train)
Y_pred = clf4.predict(X_test)
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))


# In[55]:


print('KNN Classifier')
clf5 = KNeighborsClassifier()
clf5.fit(X_train,Y_train)
Y_pred = clf5.predict(X_test)
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))


# # Hyper parameter tuning using GridSearch CV

# In[56]:


print('Decision Tree Classifier')
param_grid = {"criterion" : ["gini", "entropy"],
              "max_depth": [3,5,20,30],
              "splitter" : ["best","random"]
             }
griddt = GridSearchCV(estimator=clf1, param_grid=param_grid)
griddt.fit(X_train,Y_train)
print(griddt)
# summarize the results of the grid search
print(griddt.best_score_)
print(griddt.best_estimator_.max_depth)
print(griddt.best_estimator_.criterion)
print(griddt.best_estimator_.splitter)


# In[57]:


print('Adaboost Classifier')
param_grid = {"learning_rate" : [1,2,3,5,6],
              "n_estimators": [5,10,15,25,50],
              }
griddt = GridSearchCV(estimator=clf2, param_grid=param_grid)
griddt.fit(X_train,Y_train)
print(griddt)
# summarize the results of the grid search
print(griddt.best_score_)
print(griddt.best_estimator_.learning_rate)
print(griddt.best_estimator_.n_estimators)


# In[58]:


print('Logistic Regression Classifier')
param_grid = {"penalty" : ["l1","l2"],
              "C": [0.1,0.5,1,1.5],
              }
griddt = GridSearchCV(estimator=clf3, param_grid=param_grid)
griddt.fit(X_train,Y_train)
print(griddt)
# summarize the results of the grid search
print(griddt.best_score_)
print(griddt.best_estimator_.penalty)
print(griddt.best_estimator_.C)


# In[59]:


print('KNN Classifier')
param_grid = {"n_neighbors" : [1,2,3,4,5],
              "weights": ["uniform","distance"],
              }
griddt = GridSearchCV(cv=5,estimator=clf5, param_grid=param_grid)
griddt.fit(X_train,Y_train)
print(griddt)
# summarize the results of the grid search
print(griddt.best_score_)
print(griddt.best_estimator_.n_neighbors)
print(griddt.best_estimator_.weights)


# # Training and validating the classifiers with tuned hyper parameters using learning curves

# In[60]:


print('Decision Tree Classifier')
clf1 = tree.DecisionTreeClassifier(max_depth =30 , criterion = 'gini', splitter = 'random')
clf1.fit(X_train,Y_train)
scores_1 = cross_val_score(clf1, X_train, Y_train, cv=5)
print("Accuracy: %f (+/- %0.2f)" % (scores_1.mean(), scores_1.std() * 2))
train_sizes, train_scores,validation_scores = learning_curve(clf1,X_train,Y_train,cv=5,scoring='accuracy', n_jobs=-1,train_sizes=np.linspace(0.01, 1.0, 50)
)
train_mean = np.mean(1-train_scores, axis=1)
validation_mean = np.mean(1-validation_scores, axis=1)
plt.plot(train_sizes, validation_mean, label = 'Validation error')
plt.plot(train_sizes, train_mean, label = 'training error')
plt.legend()


# In[61]:


print('Adaboost Classifier')
clf2 = AdaBoostClassifier(learning_rate = 1, n_estimators = 50)
clf2.fit(X_train,Y_train)
scores_2 = cross_val_score(clf2, X_train, Y_train, cv=5)
print("Accuracy: %f (+/- %0.2f)" % (scores_2.mean(), scores_2.std() * 2))
train_sizes, train_scores,validation_scores = learning_curve(clf2,X_train,Y_train,cv=5,scoring='accuracy', n_jobs=-1,train_sizes=np.linspace(0.01, 1.0, 50)
)
train_mean = np.mean(1-train_scores, axis=1)
validation_mean = np.mean(1-validation_scores, axis=1)
plt.plot(train_sizes, train_mean, label = 'training error')
plt.plot(train_sizes, validation_mean, label = 'Validation error')
plt.legend()


# In[64]:


print('Gaussian NB Classifier')
clf4 = GaussianNB()
clf4.fit(X_train,Y_train)
scores_4 = cross_val_score(clf4, X_train, Y_train, cv=5)
print("Accuracy: %f (+/- %0.2f)" % (scores_4.mean(), scores_4.std() * 2))
train_sizes, train_scores,validation_scores = learning_curve(clf4,X_train,Y_train,cv=5,scoring='accuracy', n_jobs=-1,train_sizes=np.linspace(0.01, 1.0, 50)
)
train_mean = np.mean(1-train_scores, axis=1)
validation_mean = np.mean(1-validation_scores, axis=1)
plt.plot(train_sizes, train_mean, label = 'training error')
plt.plot(train_sizes, validation_mean, label = 'Validation error')
plt.legend()


# In[65]:


print('KNN Classifier')
clf5 = KNeighborsClassifier(n_neighbors = 4, weights = 'distance')
clf5.fit(X_train,Y_train)
scores_5 = cross_val_score(clf5, X_train, Y_train, cv=5)
print("Accuracy: %f (+/- %0.2f)" % (scores_5.mean(), scores_5.std() * 2))
train_sizes, train_scores,validation_scores = learning_curve(clf5,X_train,Y_train,cv=5,scoring='accuracy', n_jobs=-1,train_sizes=np.linspace(0.01, 1.0, 50)
)
train_mean = np.mean(1-train_scores, axis=1)
validation_mean = np.mean(1-validation_scores, axis=1)
plt.plot(train_sizes, train_mean, label = 'training error')
plt.plot(train_sizes, validation_mean, label = 'Validation error')
plt.legend()


# # Boxplot of error vs classifiers

# # Reducing the variance of best classifier (DT)

# In[67]:


print('Decision Tree Classifier')
clf1 = tree.DecisionTreeClassifier(max_depth =7, criterion = 'gini', splitter = 'best')
clf1.fit(X_train,Y_train)
scores_1 = cross_val_score(clf1, X_train, Y_train, cv=10)
print("Accuracy: %f (+/- %0.2f)" % (scores_1.mean(), scores_1.std() * 2))
train_sizes, train_scores,validation_scores = learning_curve(clf1,X_train,Y_train,cv=5,scoring='accuracy', n_jobs=-1,train_sizes=np.linspace(0.01, 1.0, 50)
)
train_mean = np.mean(1-train_scores, axis=1)
validation_mean = np.mean(1-validation_scores, axis=1)
plt.plot(train_sizes, validation_mean, label = 'Validation error')
plt.plot(train_sizes, train_mean, label = 'training error')
plt.legend()


# # Testing the best classifier (DT)

# In[68]:


print('Decision Tree Classifier')
Y_pred = clf1.predict(X_test)
from sklearn import metrics
print('Accuraccy : %f' % metrics.accuracy_score(Y_test, Y_pred))
cm = confusion_matrix(Y_test,Y_pred)
cr = classification_report(Y_test,Y_pred)
sns.heatmap(cm,annot=True,cbar=True,xticklabels='auto',yticklabels='auto')
print(cr)


# # Transfer learning of best classifier on new dataset using DT

# In[69]:


dftl=pd.read_csv("url transfer dataset.csv",delimiter = ',',encoding = 'unicode_escape', low_memory = False)


# In[70]:


dftl.describe()


# In[71]:


featureSettl = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))


# In[72]:


for i in range(len(dftl)):
    featurestl = getFeatures(dftl["domain"].loc[i], dftl["label"].loc[i])    
    featureSettl.loc[i] = featurestl


# In[73]:


featureSettl.info()


# In[74]:


featureSettl.head()


# In[75]:


X_testtl=featureSettl.iloc[:,1:11].values
Y_testtl=featureSettl.iloc[:,11].values
print(X_testtl.shape)
print(Y_testtl.shape)


# In[76]:


print('Decision Tree Classifier')
Y_predtl = clf1.predict(X_testtl)
print('Accuraccy : %f' % metrics.accuracy_score(Y_testtl, Y_predtl))
cm = confusion_matrix(Y_testtl, Y_predtl)
cr = classification_report(Y_testtl, Y_predtl)
sns.heatmap(cm,annot=True,cbar=True,xticklabels='auto',yticklabels='auto')
print(cr)


# # Demo using DT

# In[77]:


result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))
results = getFeatures('https://www.google.com/', '')
result.loc[0] = results
result = result.drop(['url','label'],axis=1).values
print(clf1.predict(result))


# In[97]:


result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))
results = getFeatures('https://lms.vit.ac.in/login/index.php', '')
result.loc[0] = results
result = result.drop(['url','label'],axis=1).values
print(clf1.predict(result))


# In[100]:


def check(url):
        result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','label'))
        results = getFeatures('url', '')
        result.loc[0] = results
        result = result.drop(['url','label'],axis=1).values
        return clf1.predict(result)[0]


# In[101]:


check('https://lms.vit.ac.in/login/index.php')


# In[ ]:




