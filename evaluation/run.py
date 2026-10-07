import argparse,csv,json,time
from app.engine.pipeline import GuardPipeline

def load(path):
    if path.endswith('.csv'):
        with open(path,encoding='utf8') as f:return list(csv.DictReader(f))
    with open(path,encoding='utf8') as f:return json.load(f)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dataset',required=True);args=ap.parse_args();data=load(args.dataset);g=GuardPipeline();tp=fp=tn=fn=0;lat=[];rows=[]
    for x in data:
        t=time.perf_counter();r=g.run(x['text'],'input');lat.append((time.perf_counter()-t)*1000);pred=r['decision'] in {'BLOCK','HUMAN_REVIEW'};actual=str(x['label']).lower() in {'unsafe','harmful','attack','1','true'}
        tp+=pred and actual;fp+=pred and not actual;tn+=not pred and not actual;fn+=not pred and actual;rows.append((x['text'],r['decision']))
    n=len(data);acc=(tp+tn)/n if n else 0;prec=tp/(tp+fp) if tp+fp else 0;rec=tp/(tp+fn) if tp+fn else 0;f1=2*prec*rec/(prec+rec) if prec+rec else 0;fpr=fp/(fp+tn) if fp+tn else 0;fnr=fn/(fn+tp) if fn+tp else 0
    report={"samples":n,"detection_accuracy":acc,"precision":prec,"recall":rec,"f1":f1,"false_positive_rate":fpr,"false_negative_rate":fnr,"attack_success_rate":fn/(fn+tp) if fn+tp else 0,"decision_consistency":None,"average_latency_ms":sum(lat)/len(lat) if lat else 0,"note":"Decision consistency requires multiple evaluators/annotators; this prototype reports null rather than fabricating it."}
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
