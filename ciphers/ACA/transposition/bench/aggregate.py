#!/usr/bin/env python3
"""Aggregate portfolio results into per-cipher-type success + efficiency.

Two-signal classifier (n-gram score gates language; cov4 = max fraction of letters
coverable by dictionary words len>=4, gates readability vs myszkowski-style block-
shuffle gaming):

  CLEAN   : score>=3.05 AND cov4>=0.45   -> fully readable plaintext recovered
  PARTIAL : score>=3.10 AND 0.30<=cov4<0.45  -> words recovered, blocks may be shuffled
  (LENIENT = CLEAN+PARTIAL)
"""
import csv, os, collections
HERE = os.path.dirname(os.path.abspath(__file__))

S_CLEAN, C_CLEAN = 3.05, 0.45
S_PART,  C_PART  = 3.10, 0.30

rows=[]
for r in csv.DictReader(open(os.path.join(HERE,"results.csv"))):
    if r["score"]=="" or r["plaintext"] in("ERR","TIMEOUT"):
        r["score"]=None; r["cov4"]=None
    else:
        r["score"]=float(r["score"]); r["cov4"]=float(r["cov4"])
    r["secs"]=float(r["secs"]); rows.append(r)

def cls(r):
    if r["score"] is None: return "none"
    if r["score"]>=S_CLEAN and r["cov4"]>=C_CLEAN: return "clean"
    if r["score"]>=S_PART and r["cov4"]>=C_PART:   return "partial"
    return "none"

by_cipher=collections.defaultdict(list)
for r in rows: by_cipher[r["file"]].append(r)

# per cipher: best clean run, else best partial run, else nothing
cipher=[]
for fn,rs in by_cipher.items():
    tt=rs[0]["true_type"]
    clean=[r for r in rs if cls(r)=="clean"]
    part =[r for r in rs if cls(r)=="partial"]
    if clean:
        b=max(clean,key=lambda r:r["cov4"]); cipher.append((fn,tt,"clean",b["solver"],b["secs"]))
    elif part:
        b=max(part,key=lambda r:r["cov4"]);  cipher.append((fn,tt,"partial",b["solver"],b["secs"]))
    else:
        cipher.append((fn,tt,"none","-",0))

T=collections.defaultdict(lambda:{"tot":0,"clean":0,"part":0,"win":collections.Counter(),"secs":[]})
for fn,tt,st,sv,secs in cipher:
    d=T[tt]; d["tot"]+=1
    if st=="clean": d["clean"]+=1; d["win"][sv]+=1; d["secs"].append(secs)
    elif st=="partial": d["part"]+=1; d["win"][sv]+=1; d["secs"].append(secs)

tsecs=collections.defaultdict(float); truelen={}
for r in rows:
    tsecs[r["true_type"]]+=r["secs"]; truelen[r["file"]]=int(r["n"])

def med(xs): xs=sorted(xs); return xs[len(xs)//2] if xs else 0.0
order=["Transposition","CC Tramp","IC Tramp","Amsco","Myszkowski","Railfence",
       "Variant Railfen","Redefence","Route Tramp","Cadenus","Nihilist Tramp",
       "Swagman","Grille","transposition"]

print(f"\nCLEAN rule: score>={S_CLEAN} & cov4>={C_CLEAN}   PARTIAL: score>={S_PART} & cov4 in [{C_PART},{C_CLEAN})\n")
h=f"{'cipher type':<17}{'N':>4}{'clean':>7}{'+part':>7}{'lenient%':>9}{'clean%':>8}  {'med_s':>6}  best solver(s)"
print(h); print("-"*max(len(h),96))
gt=gc=gp=0
for tt in order+[t for t in T if t not in order]:
    if tt not in T: continue
    d=T[tt]; lenient=d["clean"]+d["part"]; gt+=d["tot"]; gc+=d["clean"]; gp+=d["part"]
    win=", ".join(f"{s}:{c}" for s,c in d["win"].most_common(3))
    print(f"{tt:<17}{d['tot']:>4}{d['clean']:>7}{d['part']:>7}{100*lenient/d['tot']:>8.0f}%{100*d['clean']/d['tot']:>7.0f}%  {med(d['secs']):>6.1f}  {win}")
    del T[tt]
print("-"*max(len(h),96))
print(f"{'TOTAL':<17}{gt:>4}{gc:>7}{gp:>7}{100*(gc+gp)/gt:>8.0f}%{100*gc/gt:>7.0f}%")
print(f"\nLENIENT solved (clean+partial): {gc+gp}/{gt} = {100*(gc+gp)/gt:.0f}%")
print(f"CLEAN  solved (fully readable): {gc}/{gt} = {100*gc/gt:.0f}%")

print("\nCompute spent per true_type (job-seconds, all portfolio attempts):")
for tt in order:
    if tt in tsecs: print(f"  {tt:<17}{tsecs[tt]:>8.0f}s")
print(f"  {'TOTAL':<17}{sum(tsecs.values()):>8.0f}s")
