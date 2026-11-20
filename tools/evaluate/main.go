// Command evaluate reports reproducible metrics on the labelled synthetic corpus.
package main

import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "time"
 "webaudit/audit"
)
type Request struct{Target string `json:"target"`;Status int `json:"status"`;Repeat int `json:"repeat"`;UA string `json:"user_agent"`;Method string `json:"method"`;Step int `json:"step"`;Bytes int64 `json:"bytes"`}
type Case struct{ID string `json:"id"`;Category string `json:"category"`;Malicious bool `json:"malicious"`;Requests []Request `json:"requests"`;Expected string `json:"expected_outcome"`;Truth string `json:"ground_truth"`}
type Counts struct{Total int `json:"total"`;Detected int `json:"detected"`}
func main(){if err:=evaluate();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
func evaluate()error{
 p:="testdata/corpus.json";if len(os.Args)>1{p=os.Args[1]};b,err:=os.ReadFile(p);if err!=nil{return err};var cases []Case;if err=json.Unmarshal(b,&cases);err!=nil{return err}
 d,err:=os.MkdirTemp("","webaudit-eval-");if err!=nil{return err};defer os.RemoveAll(d)
 tp,fp,fn,tn,unknown,policy,policyTotal,known,answered,correct:=0,0,0,0,0,0,0,0,0,0
 categories:=map[string]Counts{};var details []map[string]any
 for _,c:=range cases{
  var lines strings.Builder;index:=0;elapsed:=0
  for _,q:=range c.Requests{for i:=0;i<q.Repeat;i++{target:=strings.ReplaceAll(q.Target,"{i}",strconv.Itoa(i));if strings.Contains(target,"?"){target+="&wa_nonce="+strconv.Itoa(index)}else{target+="?wa_nonce="+strconv.Itoa(index)}
   ts:=time.Date(2026,11,1,0,0,0,0,time.UTC).Add(time.Duration(elapsed)*time.Second).Format("02/Jan/2006:15:04:05 -0700")
   fmt.Fprintf(&lines,"192.0.2.1 - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n",ts,q.Method,target,q.Status,q.Bytes,q.UA);elapsed+=q.Step;index++
  }}
  f:=filepath.Join(d,"case.log");if err=os.WriteFile(f,[]byte(lines.String()),0600);err!=nil{return err};r:=audit.Analyze([]string{f},audit.Options{})
  detected:=len(r.Findings)>0;outcome:="unknown";if r.Outcomes["possible_success"]>0{outcome="possible_success"}else if r.Outcomes["likely_failed"]>0{outcome="likely_failed"}
  if detected&&c.Malicious{tp++}else if detected{fp++}else if c.Malicious{fn++}else{tn++}
  if c.Malicious{v:=categories[c.Category];v.Total++;if detected{v.Detected++};categories[c.Category]=v;if outcome=="unknown"{unknown++};if c.Expected!=""{policyTotal++;if outcome==c.Expected{policy++}}}
  if c.Truth!="unknown"{known++;if outcome!="unknown"{answered++;if outcome=="possible_success"&&c.Truth=="success"||outcome=="likely_failed"&&c.Truth=="failed"{correct++}}}
  details=append(details,map[string]any{"id":c.ID,"malicious":c.Malicious,"detected":detected,"outcome":outcome,"partial":r.Partial,"unparsed":r.Unparsed})
 }
 div:=func(a,b int)float64{if b==0{return 0};return float64(a)/float64(b)}
 precision,recall:=div(tp,tp+fp),div(tp,tp+fn);f1:=0.0;if precision+recall>0{f1=2*precision*recall/(precision+recall)}
 result:=map[string]any{"dataset":"synthetic calibration only; no production guarantee","cases":len(cases),"TP":tp,"FP":fp,"FN":fn,"TN":tn,"precision":precision,"recall":recall,"f1":f1,"false_positive_rate":div(fp,fp+tn),"category_detection":categories,"outcome_unknown_rate":div(unknown,tp+fn),"outcome_policy_accuracy":div(policy,policyTotal),"outcome_known_truth_cases":known,"outcome_answered":answered,"outcome_conditional_accuracy":div(correct,answered),"outcome_accuracy_counting_abstentions":div(correct,known),"details":details}
 enc:=json.NewEncoder(os.Stdout);enc.SetIndent("","  ");return enc.Encode(result)
}
