package audit

import (
 "testing"
 "time"
 "encoding/json"
 "os"
 "strings"
)

func sourceEvent(i int) Event {
 return Event{Time:time.Date(2026,1,1,0,0,0,0,time.UTC).Add(time.Duration(i)*time.Second),IP:"192.0.2.1",LogType:"http_access-log",Method:ptr("POST"),Target:"/login",Path:"/login",Status:ptr(401),File:"access.log",Line:int64(i+1)}
}
func TestUpstreamMultiplicityAndGrouping(t *testing.T) {
 u:=NewUpstream(Options{})
 for i:=0;i<6;i++ {e:=sourceEvent(0);e.Line=int64(i+1);u.Observe(e)}
 a:=u.AlertsFor("LePresidente/http-generic-401-bf")
 if len(a)!=1 || a[0].Count!=6 || len(a[0].Events)!=6 {t.Fatalf("same requests must overflow capacity 5: %+v",a)}
 u=NewUpstream(Options{})
 for i:=0;i<12;i++ {e:=sourceEvent(0);e.Target="/"+strings.Repeat("x",i);u.Observe(e)}
 if len(u.AlertsFor("LePresidente/http-generic-401-bf"))!=0 {t.Fatal("401 bucket must group by IP AND full target")}
}
func TestUpstreamLeakDistinctAndBlackhole(t *testing.T) {
 u:=NewUpstream(Options{})
 for i:=0;i<20;i++ {u.Observe(sourceEvent(i*11))}
 if len(u.AlertsFor("LePresidente/http-generic-401-bf"))!=0 {t.Fatal("tokens must refill")}
 u=NewUpstream(Options{})
 for _,sec:=range []int{0,1,2,3,4,5,20,21,22,23,24,25,61,62,63,64,65,66} {u.Observe(sourceEvent(sec))}
 if len(u.AlertsFor("LePresidente/http-generic-401-bf"))!=2 {t.Fatalf("suppressed overflow must reset bucket without extending blackhole: %+v",u.AlertsFor("LePresidente/http-generic-401-bf"))}
 u=NewUpstream(Options{})
 for i:=0;i<12;i++ {e:=sourceEvent(0);e.Status=ptr(404);e.Target="/wp-a.php";u.Observe(e)}
 if len(u.AlertsFor("crowdsecurity/http-wordpress-scan"))!=0 {t.Fatal("distinct target required")}
 for _,p:=range []string{"/wp-b.php","/wp-c.php","/wp-d.php"} {e:=sourceEvent(0);e.Status=ptr(404);e.Target=p;u.Observe(e)}
 if len(u.AlertsFor("crowdsecurity/http-wordpress-scan"))!=1 {t.Fatal("four distinct targets overflow capacity three")}
}
func TestUpstreamVendoredManifest(t *testing.T) {
 var manifest struct {Files map[string]string}
 b,err:=os.ReadFile("upstream/manifest.json");if err!=nil {t.Fatal(err)}
 if err=json.Unmarshal(b,&manifest);err!=nil || len(manifest.Files)<18 {t.Fatal("missing pinned source data",err)}
}
