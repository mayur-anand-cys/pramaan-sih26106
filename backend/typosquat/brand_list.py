"""
Brand protection list — top Indian brands most targeted by phishing.
Sources: CERT-In advisories, Digital Safe India reports, public phishing datasets.
"""
TOP_INDIAN_BRANDS = [
    # Banking & Financial Services
    {"name": "State Bank of India", "domain": "sbi.co.in", "aliases": ["sbi", "onlinesbi"], "keywords": ["login", "secure", "netbanking"]},
    {"name": "HDFC Bank", "domain": "hdfcbank.com", "aliases": ["hdfc"], "keywords": ["login", "netbanking"]},
    {"name": "ICICI Bank", "domain": "icicibank.com", "aliases": ["icici"], "keywords": ["login", "netbanking"]},
    {"name": "Axis Bank", "domain": "axisbank.com", "aliases": ["axis"], "keywords": ["login"]},
    {"name": "Kotak Mahindra Bank", "domain": "kotak.com", "aliases": ["kotak"], "keywords": ["login"]},
    {"name": "Punjab National Bank", "domain": "pnbindia.in", "aliases": ["pnb"], "keywords": ["login"]},
    {"name": "Bank of Baroda", "domain": "bankofbaroda.in", "aliases": ["bob"], "keywords": ["login"]},
    {"name": "Canara Bank", "domain": "canarabank.com", "aliases": ["canara"], "keywords": ["login"]},
    {"name": "IndusInd Bank", "domain": "indusind.com", "aliases": ["indusind"], "keywords": ["login"]},
    {"name": "Yes Bank", "domain": "yesbank.in", "aliases": ["yes"], "keywords": ["login"]},
    {"name": "IDFC First Bank", "domain": "idfcfirstbank.com", "aliases": ["idfc"], "keywords": ["login"]},
    {"name": "Federal Bank", "domain": "federalbank.co.in", "aliases": ["federal"], "keywords": ["login"]},
    {"name": "RBL Bank", "domain": "rblbank.com", "aliases": ["rbl"], "keywords": ["login"]},
    {"name": "Union Bank of India", "domain": "unionbankofindia.co.in", "aliases": ["unionbank"], "keywords": ["login"]},
    {"name": "Bank of India", "domain": "bankofindia.co.in", "aliases": ["boi"], "keywords": ["login"]},
    {"name": "Central Bank of India", "domain": "centralbankofindia.co.in", "aliases": ["centralbank"], "keywords": ["login"]},
    {"name": "Indian Bank", "domain": "indianbank.in", "aliases": ["indianbank"], "keywords": ["login"]},
    {"name": "UCO Bank", "domain": "ucobank.com", "aliases": ["uco"], "keywords": ["login"]},
    {"name": "AU Small Finance Bank", "domain": "aubank.in", "aliases": ["au"], "keywords": ["login"]},
    {"name": "Bajaj Finserv", "domain": "bajajfinserv.in", "aliases": ["bajaj"], "keywords": ["login", "emi"]},

    # Payment & Fintech
    {"name": "Paytm", "domain": "paytm.com", "aliases": ["paytm"], "keywords": ["login", "wallet", "kyc"]},
    {"name": "PhonePe", "domain": "phonepe.com", "aliases": ["phonepe"], "keywords": ["login", "wallet"]},
    {"name": "Google Pay India", "domain": "pay.google.com", "aliases": ["gpay", "googlepay"], "keywords": ["login", "wallet"]},
    {"name": "Amazon Pay India", "domain": "amazonpay.in", "aliases": ["amazonpay"], "keywords": ["login", "wallet"]},
    {"name": "Mobikwik", "domain": "mobikwik.com", "aliases": ["mobikwik"], "keywords": ["login", "wallet"]},
    {"name": "Freecharge", "domain": "freecharge.in", "aliases": ["freecharge"], "keywords": ["login"]},
    {"name": "Razorpay", "domain": "razorpay.com", "aliases": ["razorpay"], "keywords": ["login", "payment"]},
    {"name": "BharatPe", "domain": "bharatpe.com", "aliases": ["bharatpe"], "keywords": ["login", "merchant"]},
    {"name": "CRED", "domain": "cred.club", "aliases": ["cred"], "keywords": ["login", "credit"]},

    # E-commerce & Retail
    {"name": "Flipkart", "domain": "flipkart.com", "aliases": ["flipkart"], "keywords": ["login", "order", "offer"]},
    {"name": "Amazon India", "domain": "amazon.in", "aliases": ["amazon"], "keywords": ["login", "order"]},
    {"name": "Myntra", "domain": "myntra.com", "aliases": ["myntra"], "keywords": ["login", "order"]},
    {"name": "Ajio", "domain": "ajio.com", "aliases": ["ajio"], "keywords": ["login", "order"]},
    {"name": "Nykaa", "domain": "nykaa.com", "aliases": ["nykaa"], "keywords": ["login", "order"]},
    {"name": "Snapdeal", "domain": "snapdeal.com", "aliases": ["snapdeal"], "keywords": ["login", "order"]},
    {"name": "Meesho", "domain": "meesho.com", "aliases": ["meesho"], "keywords": ["login", "order"]},
    {"name": "Tata Cliq", "domain": "tatacliq.com", "aliases": ["tatacliq", "tata"], "keywords": ["login", "order"]},
    {"name": "Croma", "domain": "croma.com", "aliases": ["croma"], "keywords": ["login", "order"]},
    {"name": "Reliance Digital", "domain": "reliancedigital.in", "aliases": ["reliance"], "keywords": ["login", "order"]},
    {"name": "DMart", "domain": "dmart.in", "aliases": ["dmart"], "keywords": ["login", "order"]},
    {"name": "BigBasket", "domain": "bigbasket.com", "aliases": ["bigbasket"], "keywords": ["login", "order"]},
    {"name": "Blinkit", "domain": "blinkit.com", "aliases": ["blinkit"], "keywords": ["login", "order"]},
    {"name": "Zepto", "domain": "zepto.co", "aliases": ["zepto"], "keywords": ["login", "order"]},

    # Telecom
    {"name": "Jio", "domain": "jio.com", "aliases": ["jio", "reliancejio"], "keywords": ["recharge", "login", "offer"]},
    {"name": "Airtel", "domain": "airtel.in", "aliases": ["airtel", "bhartiairtel"], "keywords": ["recharge", "login"]},
    {"name": "Vi (Vodafone Idea)", "domain": "myvi.in", "aliases": ["vi", "vodafone", "idea"], "keywords": ["recharge", "login"]},
    {"name": "BSNL", "domain": "bsnl.co.in", "aliases": ["bsnl"], "keywords": ["recharge", "login"]},
    {"name": "MTNL", "domain": "mtnl.net.in", "aliases": ["mtnl"], "keywords": ["login"]},

    # Government & Utilities
    {"name": "Income Tax India", "domain": "incometax.gov.in", "aliases": ["incometax", "itr"], "keywords": ["login", "refund", "efiling"]},
    {"name": "GST Portal", "domain": "gst.gov.in", "aliases": ["gst"], "keywords": ["login", "return"]},
    {"name": "EPFO", "domain": "epfindia.gov.in", "aliases": ["epfo", "pf"], "keywords": ["login", "passbook"]},
    {"name": "Passport Seva", "domain": "passportindia.gov.in", "aliases": ["passport"], "keywords": ["login", "appointment"]},
    {"name": "IRCTC", "domain": "irctc.co.in", "aliases": ["irctc", "railway"], "keywords": ["login", "ticket", "booking"]},
    {"name": "India Post", "domain": "indiapost.gov.in", "aliases": ["indiapost", "postoffice"], "keywords": ["tracking", "login"]},
    {"name": "UIDAI (Aadhaar)", "domain": "uidai.gov.in", "aliases": ["uidai", "aadhaar"], "keywords": ["download", "update"]},
    {"name": "DigiLocker", "domain": "digilocker.gov.in", "aliases": ["digilocker"], "keywords": ["login", "document"]},
    {"name": "MyGov", "domain": "mygov.in", "aliases": ["mygov"], "keywords": ["login"]},
    {"name": "NPS Trust", "domain": "npstrust.org.in", "aliases": ["nps"], "keywords": ["login"]},

    # Insurance
    {"name": "LIC India", "domain": "licindia.in", "aliases": ["lic"], "keywords": ["login", "premium"]},
    {"name": "HDFC ERGO", "domain": "hdfcergo.com", "aliases": ["hdfcergo"], "keywords": ["login", "claim"]},
    {"name": "ICICI Lombard", "domain": "icicilombard.com", "aliases": ["icicilombard"], "keywords": ["login", "claim"]},
    {"name": "Star Health", "domain": "starhealth.in", "aliases": ["starhealth"], "keywords": ["login", "claim"]},
    {"name": "Max Bupa", "domain": "maxbupa.com", "aliases": ["maxbupa", "nivabupa"], "keywords": ["login", "claim"]},

    # Travel & Transport
    {"name": "MakeMyTrip", "domain": "makemytrip.com", "aliases": ["makemytrip", "mmt"], "keywords": ["login", "booking"]},
    {"name": "Goibibo", "domain": "goibibo.com", "aliases": ["goibibo"], "keywords": ["login", "booking"]},
    {"name": "Cleartrip", "domain": "cleartrip.com", "aliases": ["cleartrip"], "keywords": ["login", "booking"]},
    {"name": "Yatra", "domain": "yatra.com", "aliases": ["yatra"], "keywords": ["login", "booking"]},
    {"name": "RedBus", "domain": "redbus.in", "aliases": ["redbus"], "keywords": ["login", "booking"]},
    {"name": "Ola", "domain": "olacabs.com", "aliases": ["ola", "olacabs"], "keywords": ["login", "ride"]},
    {"name": "Uber India", "domain": "uber.com", "aliases": ["uber"], "keywords": ["login", "ride"]},

    # Food Delivery
    {"name": "Zomato", "domain": "zomato.com", "aliases": ["zomato"], "keywords": ["login", "order"]},
    {"name": "Swiggy", "domain": "swiggy.com", "aliases": ["swiggy"], "keywords": ["login", "order"]},
    {"name": "Dominos India", "domain": "dominos.co.in", "aliases": ["dominos"], "keywords": ["login", "order"]},
    {"name": "McDonalds India", "domain": "mcdonaldsindia.com", "aliases": ["mcdonalds"], "keywords": ["login", "order"]},

    # Social Media & Communication
    {"name": "WhatsApp", "domain": "whatsapp.com", "aliases": ["whatsapp"], "keywords": ["login", "verify"]},
    {"name": "Facebook", "domain": "facebook.com", "aliases": ["facebook", "fb"], "keywords": ["login"]},
    {"name": "Instagram", "domain": "instagram.com", "aliases": ["instagram", "insta"], "keywords": ["login"]},
    {"name": "Twitter / X", "domain": "twitter.com", "aliases": ["twitter"], "keywords": ["login"]},
    {"name": "LinkedIn", "domain": "linkedin.com", "aliases": ["linkedin"], "keywords": ["login"]},
    {"name": "Telegram", "domain": "telegram.org", "aliases": ["telegram"], "keywords": ["login"]},

    # Technology & Cloud
    {"name": "Google India", "domain": "google.co.in", "aliases": ["google"], "keywords": ["login"]},
    {"name": "Microsoft India", "domain": "microsoft.com", "aliases": ["microsoft", "ms"], "keywords": ["login", "office"]},
    {"name": "Apple India", "domain": "apple.com", "aliases": ["apple"], "keywords": ["login", "icloud"]},
    {"name": "Netflix India", "domain": "netflix.com", "aliases": ["netflix"], "keywords": ["login", "subscription"]},
    {"name": "Amazon Web Services", "domain": "aws.amazon.com", "aliases": ["aws"], "keywords": ["login", "console"]},
    {"name": "Tata Consultancy Services", "domain": "tcs.com", "aliases": ["tcs"], "keywords": ["login", "career"]},
    {"name": "Infosys", "domain": "infosys.com", "aliases": ["infosys"], "keywords": ["login", "career"]},
    {"name": "Wipro", "domain": "wipro.com", "aliases": ["wipro"], "keywords": ["login", "career"]},
    {"name": "HCL Technologies", "domain": "hcltech.com", "aliases": ["hcl"], "keywords": ["login", "career"]},
    {"name": "Tech Mahindra", "domain": "techmahindra.com", "aliases": ["techmahindra"], "keywords": ["login", "career"]},

    # Education
    {"name": "NPTEL", "domain": "nptel.ac.in", "aliases": ["nptel"], "keywords": ["login", "course"]},
    {"name": "SWAYAM", "domain": "swayam.gov.in", "aliases": ["swayam"], "keywords": ["login", "course"]},
    {"name": "AICTE", "domain": "aicte-india.org", "aliases": ["aicte"], "keywords": ["login"]},
    {"name": "CBSE", "domain": "cbse.gov.in", "aliases": ["cbse"], "keywords": ["login", "result"]},
    {"name": "NTA (JEE/NEET)", "domain": "nta.ac.in", "aliases": ["nta"], "keywords": ["login", "admitcard"]},

    # Healthcare
    {"name": "Apollo Hospitals", "domain": "apollohospitals.com", "aliases": ["apollo"], "keywords": ["login", "appointment"]},
    {"name": "Fortis Healthcare", "domain": "fortishealthcare.com", "aliases": ["fortis"], "keywords": ["login", "appointment"]},
    {"name": "Max Healthcare", "domain": "maxhealthcare.in", "aliases": ["maxhealthcare"], "keywords": ["login", "appointment"]},
    {"name": "PharmEasy", "domain": "pharmeasy.in", "aliases": ["pharmeasy"], "keywords": ["login", "medicine"]},
    {"name": "1mg", "domain": "1mg.com", "aliases": ["1mg", "tatamg"], "keywords": ["login", "medicine"]},
    {"name": "Netmeds", "domain": "netmeds.com", "aliases": ["netmeds"], "keywords": ["login", "medicine"]},

    # Energy & Infrastructure
    {"name": "ONGC", "domain": "ongcindia.com", "aliases": ["ongc"], "keywords": ["login"]},
    {"name": "NTPC", "domain": "ntpc.co.in", "aliases": ["ntpc"], "keywords": ["login"]},
    {"name": "BHEL", "domain": "bhel.com", "aliases": ["bhel"], "keywords": ["login"]},
    {"name": "Adani Group", "domain": "adani.com", "aliases": ["adani"], "keywords": ["login"]},
    {"name": "Reliance Industries", "domain": "ril.com", "aliases": ["reliance", "ril"], "keywords": ["login"]},
    {"name": "Tata Group", "domain": "tata.com", "aliases": ["tata"], "keywords": ["login"]},
    {"name": "Mahindra", "domain": "mahindra.com", "aliases": ["mahindra"], "keywords": ["login"]},
    {"name": "Bajaj Auto", "domain": "bajajauto.com", "aliases": ["bajajauto"], "keywords": ["login"]},
    {"name": "Hero MotoCorp", "domain": "heromotocorp.com", "aliases": ["hero"], "keywords": ["login"]},
    {"name": "TVS Motor", "domain": "tvsmotor.com", "aliases": ["tvs"], "keywords": ["login"]},
]


# International brands heavily targeted in India
TOP_INDIAN_BRANDS.extend([
    {"name": "PayPal", "domain": "paypal.com", "aliases": ["paypal"], "keywords": ["login", "verify"]},
    {"name": "Amazon Global", "domain": "amazon.com", "aliases": ["amazon"], "keywords": ["login", "order"]},
    {"name": "Google Global", "domain": "google.com", "aliases": ["google", "gmail"], "keywords": ["login"]},
])

BRAND_BY_DOMAIN = {b["domain"]: b for b in TOP_INDIAN_BRANDS}


def get_all_brand_domains():
    return set(BRAND_BY_DOMAIN.keys())


def get_all_aliases():
    aliases = set()
    for b in TOP_INDIAN_BRANDS:
        aliases.update(a.lower() for a in b.get("aliases", []))
    return aliases


def find_brand_by_domain(domain: str):
    return BRAND_BY_DOMAIN.get(domain.lower())
