## Crawler Design 

This prototypal web crawler design is 
purely for learning purposes and a 'non-distributed' adaptation from the paper on *Web Crawling* by [Christopher Olston and Marc Najork]()

Each crawling process consists of multiple workers, and each 
worker performs a repeated work cycle, the workers would run concurrently.

At the beginning of each work cycle, a worker obtains a URL from 
the *Frontier* data structure, which dispenses URLs according to 
their priority and to politeness policies. 

The worker then invokes the *HTTP fetcher*. 
The *fetchter* connects to the web server, checks for a robots.txt file for exclusion rules and attempts to download the web page.

If the download succeeds, the web page may or may not be stored in a repository of harvested web pages.

In either case, the page is passed to the *link extractor* which parses the page's HTML content and extracts hyperlinks contained therein. 

The corresponding URLs are then passed to a *URL distributor*, which assigns each URL to a crawling process.

Next, the URL passes through the *Custom URL filter* (eg. to exclude URLs belinging to **blacklisted** sites, or URLs with particular file extensions that are not of interest) and into the *Duplicate URL eliminator*, which maintains the set of all URLs discovered so far and passes on only *never-before-seen* URLs.

Finally the *URL prioritizer* selects a position for the URL in the URL frontier, based on factors such as estimated page importance or rate of change.

KEY DESIGN POINTS 

The crawler downloads web pages by starting from one or more *seed URLs*, downloading each of the associated pages, extracting the hyperlink URLs contained therein, and recursively downloading those pages. 


To meet this need, the crawler needs:
*   To track both of the URLs that are to be downloaded, as well as those that are have already been downloaded (to avoid unintentionally downloading the same page repeatedly). 
    
*   The required state is a {set} of URLs, each associated with a flag indicating whether the page has been downloaded.

*   The operations that must be supported are:
    **Adding** a new URL
    **Retreiving** a URL, 
    **Marking** a URL as downloaded 
    **Testing** whether the set contains a URL 

* Memory management 
    There are many alternative in-memory data structures (eg.trees or sorted lists) that support these operations. However, such implementation does not scale to web sorpus sizes that exceed the amount of memory available on a single machine.
    To scale beyond this limitation, one could either maintain teh data structure(eg. tree or sorted list) on disk, or use an off-the-shelf database management system. 
    
