#!/usr/local/bin/python3
import dns.resolver, warnings,sys
from ipwhois import IPWhois
import json

domain = sys.argv[1]

services = set()

txtrecords = {
    "docusign":"DocuSign",
    "facebook-domain-verification":"Facebook Business Manager",
    "google-site-verification":"G Suite",
    "adobe-sign-verification":"Adobe Sign",
    "atlassian-domain-verification":"Atlassian",
    "MS":"Microsoft Office 365",
    "adobe-idp-site-verification":"Adobe Enterprise",
    "yandex-verification":"Yandex",
    "_amazonses":"Amazon Simple Email Services",
    "logmein-verification-code":"LogMeIn",
    "citrix-verification-code":"Citrix Services",
    "pardot":"Salesforce",
    "zuora":"Zuora"
}

cnamerecords = {
    "autodiscover.":"Microsoft Exchange",
    "lyncdiscover.":"Microsoft Lync",
    "sip.":"Microsoft SIP Services",
    "enterpriseregistration.":"Mobile Device Management (MDM) services",
    "enterpriseenrollment.":"Mobile Device Management (MDM) services",
    "adfs.":"Active Directory Federated Services",
    "sts.":"Security Token Service"
}

asnproviders = {
    "MICROSOFT":"Microsoft Corporation",
    "GOOGLE":"Google (Alphabet) Corporation",
    "AirWatch LLC":"AirWatch Mobile Device Management"
}

cnameproviders = {
    "outlook":"Microsoft Office 365 (Managed Exchange)",
    "awmdm.com":"Airwatch Mobile Device Management (MDM)",
    "lync.com":"Microsoft Hosted Lync"
}

spfrecords = {
    "_spf.salesforce.com":"Salesforce.com",
    "_spf.google.com":"G Suite",
    "protection.outlook.com":"Microsoft Outlook",
    "service-now.com":"Service Now",
    "mailsenders.netsuite.com":"NetSuite",
    "mktomail.com":"Marketo",
    "spf.mandrillapp.com":"Mandrill (MailChimp)",
    "pphosted.com":"Proof Point",
    "zendesk.com":"Zendesk",
    "mcsv.net":"MailChimp",
    "freshdesk.com":"Freshdesk"
}

mxrecords = {
    "google.com":"G Suite",
    "googlemail.com":"G Suite",
    "pphosted.com":"Proof Point",
    "zoho.com":"ZOHO",
    "protection.outlook.com":"Microsoft Outlook"
}

misctxt = {
    "pardot":"Pardot Business-to-Business Marketing by Salesforce"
}

def displayhelp():
    print("EaaS - Enumeration as a Service.")
    print("Usage : ./eaas.py [domain]")

# Function to query TXT DNS entries
def querytxt():
    answers =  dns.resolver.resolve(domain,"TXT")
    for rdata in answers:
        # Examine various TXT based records for the domain
        for key, value in txtrecords.items():
            if key in rdata.to_text():
                services.add(value)                

        # Examine SPF records for the domain
        for spfkey, spfvalue in spfrecords.items():
            if spfkey in rdata.to_text():
                services.add(spfvalue)

# Function to query and examine CNAME records for the chosen domain
def querycname():
    for key, value in cnamerecords.items():
        lookup = key + domain
        try:
            answers =  dns.resolver.resolve(lookup, 'CNAME')
            for rdata in answers:
                for cnamekey, cnamevalue in cnameproviders.items():
                    if cnamekey in rdata.target.to_text():
                        services.add(cnamevalue)
        except:
            pass

# Function to query and exmaine A records for the chosen domain.
def queryarecords():
    for key, value in cnamerecords.items():
        lookup = key + domain
        try:
            answers =  dns.resolver.resolve(lookup, 'A')
            for rdata in answers:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning)
                    obj = IPWhois(str(rdata.address))
                    results = obj.lookup_rdap()
                    for asnkey, asnvalue in asnproviders.items():
                        if asnkey in format(results['asn_description']):
                            services.add(asnvalue)
        except:
            pass

# Function to query and examine the MX records for the chosen domain.
def querymxrecords():
    try:
        answers =  dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            for mxkey, mxvalue in mxrecords.items():
                if mxkey in rdata.exchange.to_text():
                    services.add(mxvalue)
    except:
        pass

if __name__ == "__main__":
    if len(sys.argv) == 1:
        displayhelp()
        sys.exit()
    else:
        querytxt()
        querycname()
        queryarecords()
        querymxrecords()

        print(json.dumps(list(services)))