package audit

import (
 "bytes"
 "encoding/csv"
 "encoding/json"
 "strings"
 "testing"
)
func TestReports(t *testing.T){
 c:=NewCorrelator(Options{});e:=incidentEvent(1,200);e.Raw=`<script>alert("bad")</script>`;e.IP="=HYPERLINK(1)";h,n:=Detect(e);c.Add(e,h,n)
 r:=Report{Version:Version,RulesVersion:RulesVersion,Findings:c.Finish(),Warnings:[]string{"Test warning"},Outcomes:map[string]int{"unknown":1},Categories:map[string]int{"sensitive_file":1}}
 for _,format:=range []string{"html","json","csv","summary"}{t.Run(format,func(t *testing.T){var b bytes.Buffer;if err:=WriteReport(&b,r,format);err!=nil{t.Fatal(err)};s:=b.String();if format=="html"&&(strings.Contains(s,"<script>")||strings.Contains(s,"https://cdn")||!strings.Contains(s,"&lt;script&gt;")){t.Fatal("unsafe HTML",s)};if format=="json"{var v Report;if err:=json.Unmarshal(b.Bytes(),&v);err!=nil||len(v.Findings)!=1{t.Fatal(err)}};if format=="csv"{rows,err:=csv.NewReader(strings.NewReader(s)).ReadAll();if err!=nil||len(rows)<3{t.Fatal(err)};if !strings.Contains(s,"'=HYPERLINK"){t.Fatal("spreadsheet formula not neutralized")}}})}
 if WriteReport(&bytes.Buffer{},r,"bad")==nil{t.Fatal("unknown format")}
}
