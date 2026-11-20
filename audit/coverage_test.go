package audit

import "testing"

func TestHubAdaptationCoverage(t *testing.T){
 for _,target:=range []string{
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/?x=@java.lang.Runtime@getRuntime().exec(id)",
  "/?x=${script:javascript:java.lang.Runtime.getRuntime().exec(id)}",
  "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
  "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
  "/public/plugins/alertlist/../../etc/passwd",
  "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
  "/wp-config.php.bak",
  "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=id",
 } {h,_:=Detect(Event{Target:target});if len(h)==0{t.Fatal(target)}}
 h,_:=Detect(Event{Protocol:ptr("HTTP/9.9")});if len(h)==0{t.Fatal("unusual protocol version not detected")}
}
func TestDuplicateJSONFieldsRejected(t *testing.T){s:=`{"remote_addr":"192.0.2.1","remote_addr":"203.0.113.1","time_iso8601":"2026-11-01T00:00:00Z","request":"GET / HTTP/1.1"}`;if _,err:=Parse(s,"a",1,"");err==nil{t.Fatal("ambiguous JSON keys accepted")}}
