# virus-total for Elementor

To Run this you need your TOTALVIRUS_API_KEY to be in the environment

---
Stack:
Using FastApi with swagger running on gunicorn
totalvirus library from pypi


1. run the main to turn on gunicorn server, it defaults to http://localhost:8000
1. to test the api using swagger go to http://localhost:8000/docs
 - the url to tes the api is /scan/url
 - the url can have a TOTALVIRUS_API_KEY header to use your APIkey and not the default one.
 
1. tracker has UrlTracker, that uses an internal db class to save the data

## features i would like to implement
1. add external queue
1. add worker that gets reports every 30 min and updates the redis
1. save the db on redis with ttl