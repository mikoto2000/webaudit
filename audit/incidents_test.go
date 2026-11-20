package audit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func incidentEvent(i,status int)Event{e:=sample(i);e.Target="/.env";e.Path="/.env";e.Status=ptr(status);e.File="a.log";e.Line=int64(i+1);e.Raw=strings.Replace(common,"200 42", "404 0",1);return e}
func TestCorrelation(t *testing.T){
 c:=NewCorrelator(Options{});for i:=0;i<3;i++{e:=incidentEvent(i,404);h,n:=Detect(e);c.Add(e,h,n)};f:=c.Finish();if len(f)!=1||f[0].Count!=3||len(f[0].Evidence)!=3||len(f[0].Correlation)==0{t.Fatalf("%+v",f)}
 e:=incidentEvent(4,404);e.Time=e.Time.Add(time.Hour);h,n:=Detect(e);c.Add(e,h,n)
 e=incidentEvent(5,404);e.UA=ptr("other");h,n=Detect(e);c.Add(e,h,n)
 e=incidentEvent(6,404);e.Host=ptr("different.example");h,n=Detect(e);c.Add(e,h,n)
 if len(c.Finish())!=4{t.Fatal("over-grouped unrelated activity")}
}
func TestOutcome(t *testing.T){
 for _,tc:=range []struct{name string;statuses []int;want string}{
  {"200 alone",[]int{200},"unknown"},{"500",[]int{500},"unknown"},{"302",[]int{302},"unknown"},{"404 alone",[]int{404},"unknown"},
  {"blocked",[]int{403,404,403},"likely_failed"},{"possible exposure",[]int{404,200,200},"possible_success"},
 }{t.Run(tc.name,func(t *testing.T){c:=NewCorrelator(Options{});for i,s:=range tc.statuses{e:=incidentEvent(i,s);h,n:=Detect(e);c.Add(e,h,n)};f:=c.Finish();if len(f)!=1||f[0].Outcome.Verdict!=tc.want||f[0].Outcome.Confidence>0.55||len(f[0].Outcome.Missing)==0||len(f[0].Outcome.Next)==0{t.Fatalf("%+v",f)}})}
}
func TestEvidenceBounds(t *testing.T){c:=NewCorrelator(Options{MaxFindings:2});for i:=0;i<100;i++{e:=incidentEvent(i,200);h,n:=Detect(e);c.Add(e,h,n)};f:=c.Finish();if len(f)!=1||len(f[0].Evidence)>8||f[0].Score>100{t.Fatal(f)};for i:=0;i<4;i++{e:=incidentEvent(i,200);e.IP=string(rune('a'+i));h,n:=Detect(e);c.Add(e,h,n)};if len(c.Finish())>2||len(c.Warnings())==0{t.Fatal("silent limit")}}
func TestAnalyzeDedup(t *testing.T){d:=t.TempDir();p:=filepath.Join(d,"access.log");line:=strings.Replace(common,"/index?q=1","/.env",1);_=os.WriteFile(p,[]byte(line+"\n"+line+"\n"),0600);r:=Analyze([]string{p},Options{});if r.Parsed!=2||r.Duplicates!=1||len(r.Findings)!=1||r.Findings[0].Count!=1{t.Fatalf("%+v",r)}}
