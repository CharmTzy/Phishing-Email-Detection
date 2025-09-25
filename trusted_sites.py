#Update the txt file with more relevant sites
def getSiteList():
    siteList=[]
    with open("trusted_sites.txt") as f:
        for x in f:
            siteList.append(x.strip('\n'))
    return siteList