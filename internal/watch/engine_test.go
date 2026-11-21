package watch
import("encoding/json";"fmt";"strings";"testing";"time";"webaudit/audit")
func event(t *testing.T,i,status int,target string)audit.Event{t.Helper();line:=fmt.Sprintf("198.51.100.20 - - [01/Nov/2026:00:00:%02d +0000] \"GET %s HTTP/1.1\" %d 100",i,status,target);e,err:=audit.Parse(line,"access.log",int64(i+1),"");if err!=nil{t.Fatal(err)};return e}
func TestEngineLifecycleOutcomeAndPrivacy(t *testing.T){
 now:=time.Date(2026,11,1,0,0,0,0,time.UTC);e:=NewEngine(EngineOptions{})
 e.Observe(event(t,0,404,"/.env?token=SECRET"),now);got:=e.Flush(now)
 if len(got)!=1||got[0].EventType!="incident_created"||got[0].Revision!=1||got[0].Outcome!="unknown"{t.Fatal(got)};id:=got[0].IncidentID
 if len(e.Flush(now))!=0{t.Fatal("unchanged emitted")}
 for i:=1;i<=2;i++{e.Observe(event(t,i,200,"/.env?token=SECRET"),now.Add(time.Duration(i)*time.Second))};got=e.Flush(now.Add(2*time.Second))
 if len(got)!=1||got[0].IncidentID!=id||got[0].Revision!=2||got[0].Outcome!="possible_success"||!got[0].Notify{t.Fatal(got)}
 b,_:=json.Marshal(e);if strings.Contains(string(b),"SECRET"){t.Fatal("secret persisted")};b,_=json.Marshal(got);if strings.Contains(string(b),"SECRET"){t.Fatal("secret emitted")}
 got=e.Flush(now.Add(20*time.Minute));if len(got)!=1||got[0].EventType!="incident_closed"||got[0].Revision!=3{t.Fatal(got)}
}
func TestEngineBehaviorLateNormalAndLimit(t *testing.T){
 var warnings []string;now:=time.Now();e:=NewEngine(EngineOptions{Warn:func(s string){warnings=append(warnings,s)},MaxEvents:40})
 for i:=0;i<21;i++{e.Observe(event(t,i,404,"/ordinary"),now)};got:=e.Flush(now);found:=false;for _,x:=range got{for _,id:=range x.RuleIDs{found=found||id=="WB-404"}};if !found{t.Fatal(got)}
 old:=event(t,0,404,"/.env");old.Time=old.Time.Add(-time.Hour);if e.Observe(old,now)||len(warnings)==0{t.Fatal("late accepted")}
 for i:=0;i<100;i++{e.Observe(event(t,21,200,"/ordinary"),now)};if len(e.Records)>40{t.Fatal("unbounded")}
 n:=NewEngine(EngineOptions{});for i:=0;i<10;i++{n.Observe(event(t,i,200,"/ordinary"),now)};if len(n.Flush(now))!=0{t.Fatal("normal false positive")}
}
func TestEngineOutOfOrderAndBatchParity(t *testing.T){
 now:=time.Now();e:=NewEngine(EngineOptions{AllowedLateness:time.Minute});a:=audit.NewAnalysis(audit.Options{});c:=audit.NewCorrelator(audit.Options{})
 for _,i:=range []int{2,0,1}{v:=event(t,i,[]int{404,200,200}[i],"/.env");e.Observe(v,now);h,n:=audit.Detect(v);a.Observe(v,h);c.Add(v,h,n)};for _,s:=range a.Finish(){c.AddSignal(s)}
 got:=e.Flush(now);want:=c.Finish();if len(got)!=len(want)||got[0].Outcome!=want[0].Outcome.Verdict||got[0].Count!=want[0].Count{t.Fatal(got,want)}
}
