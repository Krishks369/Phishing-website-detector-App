from flask import Flask, render_template, request
import pickle
import whois
from urllib.parse import urlparse
import dns.resolver
import pandas as pd
import warnings
import re

with open(f"model/phishingDetect.pkl", "rb") as f:
    model = pickle.load(f)

app = Flask(__name__, template_folder='templates')
warnings.filterwarnings("error")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


@app.route('/', methods=["GET", "POST"])
def main():
    # 1 means legitimate
    # 0 is suspicious
    # -1 is phishing
    if request.args.get("url"):
        URL = request.args.get("url")
        data = []
        # If the URL contains a IP:
        containsIP = re.match(r"^(http|https)://\d+\.\d+\.\d+\.\d+\.*", URL)
        if containsIP:
            data.append(0)
        else:
            data.append(1)
        # Check for long URL
        urlLength = len(URL)
        if urlLength < 54:
            data.append(-1)
        if urlLength > 54 and urlLength < 75:
            data.append(0)
        if urlLength >= 75:
            data.append(1)
        # Check for tinyurl
        try:
            resp = urllib.request.urlopen(URL)
            if resp.url == URL:
                data.append(1)
            else:
                data.append(-1)
        except:
            data.append(-1)
        symbol = "@"
        if symbol in URL:
            data.append(1)
        else:
            data.append(-1)
        # Redirecting or not:
        try:
            resp = urllib.request.urlopen(URL)
            if resp.url == URL:
                data.append(1)
            else:
                data.append(-1)
        except:
            data.append(-1)
        # Contains a separator:
        separator = "-"
        if separator in URL:
            data.append(-1)
        else:
            data.append(1)
        # other sub domain
        try:
            res = get_tld(URL, as_object=True)
            subdomain = res.fld.split(".")
            if (len(subdomain) <= 3):
                data.append(-1)
            elif (len(subdomain) <= 4):
                data.append(0)
            else:
                data.append(1)
        except:
            data.append(-1)
        # Validity of HTTPS request
        try:
            responce = requests.get(URL, verify=False)
            data.append(-1)
        except:
            data.append(1)
        # Check domain
        try:
            w = whois.whois(URL)
            time = datetime.datetime.now()
            exp = w["expiration_date"][0]
            if (int(exp.year)-int(time.year) > 1):
                data.append(1)
            else:
                data.append(0)
        except:
            data.append(-1)
        # Favicon Ico
        try:
            res = urllib.parse.urlsplit(URL)
            dt = urllib.request.urlopen("https://"+res.hostname+"/favicon.ico")
            data.append(1)
        except:
            data.append(-1)
        # Std Port:
        try:
            res = get_tld(URL, as_object=True)
            if re.search('[0-6553]', res.path):
                data.append(1)
            else:
                data.append(-1)
        except:
            data.append(-1)
        # CHeck for secured url
        if "https" in URL:
            data.append(1)
        else:
            data.append(-1)
        # Check for dns record
        t = urlparse(URL).netloc
        domain = t.split('.')[-2:]
        domain[0]
        try:
            nameservers = dns.resolver.query(domain[0], 'NS')
            data.append(1) if len(nameservers) > 0 else data.append(-1)
        except:
            data.append(-1)
        res = 1
        cols = [str(i*i) for i in range(13)]
        input_data = pd.DataFrame([data], columns=['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
                                                   'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
                                                   'NonStdPort', 'HTTPSDomainURL', 'DNSRecording'])
        res = model.predict(input_data)[0]
        return render_template("main.html", result=res, url=URL)
    else:
        return render_template("main.html")


if __name__ == '__main__':
    app.run()
