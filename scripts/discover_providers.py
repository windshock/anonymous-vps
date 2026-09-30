#!/usr/bin/env python3
"""Discovery-only collector for anonymous/crypto-friendly VPS provider candidates."""

from __future__ import annotations
import argparse, html, ipaddress, json, re, sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parent.parent
SOURCES_FILE=ROOT/"data"/"discovery-sources.yml"
PROVIDERS_FILE=ROOT/"data"/"providers.yml"
OUTPUT_FILE=ROOT/"generated"/"candidates"/"providers.json"
USER_AGENT="anonymous-vps-discovery/1.0 (+https://github.com/windshock/anonymous-vps)"
MAX_RESPONSE_BYTES=2_000_000
DEFAULT_EXCLUDED_DOMAINS={
 "apple.com","cloudflare.com","coingate.com","coinpayments.net","cryptomus.com",
 "facebook.com","github.com","google.com","instagram.com","linkedin.com","medium.com",
 "nowpayments.io","reddit.com","t.me","telegram.me","trustpilot.com","twitter.com",
 "x.com","youtube.com",
}

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.links=[]; self._href=None; self._text=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()=="a":
            href=dict(attrs).get("href")
            if href: self._href=href.strip(); self._text=[]
    def handle_data(self,data):
        if self._href is not None: self._text.append(data)
    def handle_endtag(self,tag):
        if tag.lower()=="a" and self._href is not None:
            label=" ".join("".join(self._text).split())
            self.links.append((self._href,html.unescape(label)))
            self._href=None; self._text=[]

def load_json(path,default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

def normalize_domain(value):
    raw=str(value or "").strip()
    if not raw: return None
    parsed=urlparse(raw if "://" in raw else "https://"+raw)
    host=(parsed.hostname or "").rstrip(".").lower()
    if host.startswith("www."): host=host[4:]
    if not host or "." not in host: return None
    try: ipaddress.ip_address(host); return None
    except ValueError: pass
    if not re.fullmatch(r"[a-z0-9.-]+",host):
        try: host=host.encode("idna").decode("ascii")
        except UnicodeError: return None
    return host

def domain_matches(domain,base):
    return domain==base or domain.endswith("."+base)

def is_excluded(domain,excluded):
    return any(domain_matches(domain,x) for x in excluded)

def known_domains(providers):
    out=set()
    for provider in providers:
        for value in provider.get("domains",[]):
            domain=normalize_domain(value)
            if domain: out.add(domain)
    return out

def is_known(domain,known):
    return any(domain_matches(domain,x) or domain_matches(x,domain) for x in known)

def fetch_html(url,timeout=20.0):
    req=Request(url,headers={"User-Agent":USER_AGENT,"Accept":"text/html,*/*;q=0.8"})
    with urlopen(req,timeout=timeout) as response:
        ctype=response.headers.get("Content-Type","")
        if ctype and "html" not in ctype.lower(): raise ValueError("unexpected content type: "+ctype)
        raw=response.read(MAX_RESPONSE_BYTES+1)[:MAX_RESPONSE_BYTES]
        charset=response.headers.get_content_charset() or "utf-8"
        return response.geturl(),raw.decode(charset,errors="replace")

def extract_external_domains(page_url,body,excluded):
    parser=LinkParser(); parser.feed(body)
    source_domain=normalize_domain(page_url); found={}
    for href,label in parser.links:
        absolute=urljoin(page_url,href); parsed=urlparse(absolute)
        if parsed.scheme not in {"http","https"}: continue
        domain=normalize_domain(absolute)
        if not domain: continue
        if source_domain and domain_matches(domain,source_domain): continue
        if is_excluded(domain,excluded): continue
        item=found.setdefault(domain,{"domain":domain,"links":[],"labels":[]})
        clean=f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if clean not in item["links"]: item["links"].append(clean)
        if label and label not in item["labels"]: item["labels"].append(label[:160])
    return found

def canonicalize(item):
    item["sources"]=sorted(item.get("sources",[]),key=lambda x:(x.get("id",""),x.get("url","")))
    item["directory_signals"]=sorted(set(item.get("directory_signals",[])))
    item["source_links"]=sorted(set(item.get("source_links",[])))[:12]
    item["labels"]=sorted(set(item.get("labels",[])))[:12]
    return item

def merge_candidate(target,domain,source,link_data):
    item=target.setdefault(domain,{
      "domain":domain,"status":"discovered","sources":[],"directory_signals":[],
      "source_links":[],"labels":[]
    })
    sr={"id":source["id"],"url":source["url"]}
    if sr not in item["sources"]: item["sources"].append(sr)
    for v in source.get("signals",[]):
        if v not in item["directory_signals"]: item["directory_signals"].append(v)
    for v in link_data.get("links",[]):
        if v not in item["source_links"]: item["source_links"].append(v)
    for v in link_data.get("labels",[]):
        if v not in item["labels"]: item["labels"].append(v)

def discover(config,providers,previous,timeout=20.0):
    known=known_domains(providers); excluded=set(DEFAULT_EXCLUDED_DOMAINS)
    for value in config.get("excluded_domains",[]):
        domain=normalize_domain(value)
        if domain: excluded.add(domain)
    candidates={}
    for item in previous:
        domain=normalize_domain(item.get("domain",""))
        if domain and not is_known(domain,known): candidates[domain]=canonicalize(dict(item))
    errors=[]
    for source in config.get("sources",[]):
        if not source.get("enabled",True): continue
        try:
            final_url,body=fetch_html(source["url"],timeout)
            found=extract_external_domains(final_url,body,excluded)
            for domain,link_data in found.items():
                if not is_known(domain,known): merge_candidate(candidates,domain,source,link_data)
            print(f"{source['id']}: {len(found)} external domain(s), {len(candidates)} total candidate(s)")
        except (HTTPError,URLError,TimeoutError,ValueError,OSError) as exc:
            msg=f"{source.get('id',source.get('url','<source>'))}: {exc}"
            errors.append(msg); print("WARNING: "+msg,file=sys.stderr)
    return [canonicalize(candidates[k]) for k in sorted(candidates)],errors

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--timeout",type=float,default=20.0)
    ap.add_argument("--strict",action="store_true")
    args=ap.parse_args()
    records,errors=discover(load_json(SOURCES_FILE,{"sources":[]}),load_json(PROVIDERS_FILE,[]),load_json(OUTPUT_FILE,[]),args.timeout)
    text=json.dumps(records,indent=2,ensure_ascii=False)+"\n"
    if args.dry_run: sys.stdout.write(text)
    else:
        OUTPUT_FILE.parent.mkdir(parents=True,exist_ok=True); OUTPUT_FILE.write_text(text,encoding="utf-8")
    print(f"Discovery complete: {len(records)} candidate provider domain(s)",file=sys.stderr if args.dry_run else sys.stdout)
    if errors: print(f"Source warnings: {len(errors)}",file=sys.stderr)
    return 1 if args.strict and errors else 0

if __name__=="__main__": raise SystemExit(main())
