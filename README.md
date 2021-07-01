# Phishing-website-detection-ML-flask

Phishing is quite a popular form of cyber-attacks these days in which the user is made to visit illegitimate websites.
In these websites, the user can be tricked into revealing his sensitive information such as username, passwords, bank details, card details, etc. Thus, it has been used quite a lot by phishers to obtain a user’s credentials. 
The phishing URLs look almost similar to the legitimate ones but actually differ in some respect. In our method, we make use of only the information about the URL of a website to determine whether the website is a phishing website or not. 
Thus, there is no need of actually visiting a website to determine whether it is phishing or not. This also allows the user to not visit the phishing websites and expose themselves to malicious codes that it may carry.
Random forest algorithm can then be applied to a dataset having such features that contain the meta data of the URLs. Random forest algorithm offers the advantage of not overfitting the data as well.

DATASET: Dataset used contains phishing URL and Non Phishing URL with label which represents whether corresponding URL is phishing URL or not.

<img src="https://github.com/anubhavmishra123/Phishing-website-detection-ML-flask/blob/main/dataset.png" width="400" height="200">

Feature Extraction: Features extracted are Number of dots, presence of hyphen, length of URL, presence of @, Number of subdirectory, Number of subdomain, length of domain, Number of queries, presence of IP, presence of suspicious TDL, presence of suspicious domain etc.

<img src="https://github.com/anubhavmishra123/Phishing-website-detection-ML-flask/blob/main/features.png" width="400" height="200">

Model Accuracy:

<img src="https://github.com/anubhavmishra123/Phishing-website-detection-ML-flask/blob/main/models.png" width="400" height="200">

Front End created using FLASK API and html

<img src="https://github.com/anubhavmishra123/Phishing-website-detection-ML-flask/blob/main/front_end.png" width="400" height="200">



