import requests, json

r = requests.get('http://54.146.141.88:3000/api/Challenges/')
data = r.json()['data']

unsolved = [c for c in data if not c.get('solved')]
keywords = ['sql','inject','xss','cross-site','admin','auth','idor','basket',
            'user','feedback','product','ssrf','xxe','xml','privilege',
            'password','login','token','jwt','ftp','null','memory','memo',
            'role','access','upload','redirect','profile','scoreboard',
            'error','metric','secret','key','encrypt','confidential',
            'manipulat','forge','tamper','overwrite','bypass','brute']

related = []
for c in unsolved:
    desc_lower = (c.get('description','') + ' ' + c.get('name','')).lower()
    if any(kw in desc_lower for kw in keywords):
        related.append(c)

print(f"=== Unsolved challenges potentially related to our findings ({len(related)}) ===\n")
for c in sorted(related, key=lambda x: x.get('difficulty',0)):
    d = c['difficulty']
    name = c['name']
    cat = c.get('category','')
    desc = c['description'][:120]
    print(f"  [{d}*] [{cat}] {name}: {desc}")

print(f"\n=== ALL unsolved ({len(unsolved)} total) ===\n")
for c in sorted(unsolved, key=lambda x: x.get('difficulty',0)):
    d = c['difficulty']
    name = c['name']
    cat = c.get('category','')
    desc = c['description'][:120]
    print(f"  [{d}*] [{cat}] {name}: {desc}")
