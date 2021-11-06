import feedparser
from datetime import datetime


feed = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog-rss.xml"

open_feed = feedparser.parse(feed, sanitize_html=True)


def retrieve_newest_entries():
    """[summary]
    """
    now = datetime.today().day
    count = 0
    for entry in open_feed.entries:
        timestamp = entry.time.get("datetime")
        if timestamp == now:
            count += 1
        print(f"{timestamp} {entry.id} {entry.a.get('href',[])}")


def search_feed_by_cve():
    """[summary]
    
    """
    cve_id = str(input('Enter a CVE (ex. CVE-YYYY-####): '))
    if not isinstance(cve_id, str):
        raise TypeError
    print()
    total_results = len(open_feed.entries)
    for idx, entry in enumerate(open_feed.entries, start=1):
        
	if cve_id in entry.id:
                      
            send_mess = f"""{idx:<2} of {total_results}  CVE: {entry.id}  
Summary: {entry.summary if len(entry.summary) is not None else ''}
URL: {entry.a.get('href', [])}
Date published: {entry.published} """
            print(send_mess)
            print()


def menu():

    print("""
    
CISA Known Exploited Vulernabilities RSS feed parser

Website: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
--------------------------------------------------------
1) Find information on recent and past CVE's CISA has identfied as being exploited in the wild. 
2) Search for newly added CVE's from the previous day.

Examples:
\t python3 cisagov_feed_parser.py -c 'CVE-2021-26411'
\t python3 cisagov_feed_parser.py -n
""")
    print('[MENU]\n')   
    print('[1]' + ' Search the RSS feed by CVE.')
    print('[2]' + ' Search for the current days newly added CVE info.')
    print('[Quit]' + " q or Q to quit\n")


def main():

    while True:
        menu()
        choice = input('Select an option from above ')
        print()
        if choice == '1':
            search_feed_by_cve()
        elif choice == '2':
            retrieve_newest_entries()
        elif choice == 'q':
            raise SystemExit
        else:
            print(f"{choice} is not one of the above options, try again...")   
   


if __name__ == '__main__':
    main()
