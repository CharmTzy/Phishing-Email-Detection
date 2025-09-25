import trusted_sites
import edit_distance
import url_detection
import keyword_detection
#Add the csv in 
keywordCheck=keyword_detection.calc_score()
trustedSites=trusted_sites.getSiteList()
emailUrls=url_detection.extract_urls()#add the email url string
urlCheck=[]
editCheck=[]
if len(emailUrls)>0:
    for i in emailUrls:
        urlCheck.append(url_detection.URLvalidator(i))#Change output to boolean
        editCheck.append(edit_distance.editDistance(trustedSites,i))
#To add, weigh the checks and return an output