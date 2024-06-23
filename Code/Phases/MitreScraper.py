# import scraping packages
from bs4 import BeautifulSoup
import requests

# list of mitre techniques codes to test
techniques = [
    "T1003",
    "T1005",
    "T1546",
    "T1059",
    "T1059.003",
    "T1059.004",
]

baseURL = 'https://attack.mitre.org/techniques/'

# check if technique contains sub technique
def isSubTechnique(technique):
    return '.' in technique

def getTactic(technique):
    # check if technique contains sub technique
    if isSubTechnique(technique):
        technique = technique.replace('.', '/')
    
    # send request to the website
    page = requests.get(baseURL + technique)
    soup = BeautifulSoup(page.content, 'html.parser')

    # Search for Tactic: or Tactics:
    tactic = soup.find('span', string='Tactic:')
    # if Tactic: is not found, search for Tactics:
    if not tactic:
        tactic = soup.find('span', string='Tactics:')
    if not tactic:
        return "Tactic not found"
    
    # get the next siblings of the tag
    tactic = tactic.find_next_siblings('a')

    # strip text from the tags
    tacticCode = [t.text.strip() for t in tactic]

    # now also get the first h1 tag of the page
    title = soup.find('h1')
    # strip text from the tag
    title = title.text.strip()

    return(tacticCode, title)

if __name__ == "__main__":
    storeTactics = {}
    for i in range(10000):
        for technique in techniques:
            if technique in storeTactics:
                print(storeTactics[technique])
            else:
                storeTactics[technique] = getTactic(technique)
                print(storeTactics[technique])