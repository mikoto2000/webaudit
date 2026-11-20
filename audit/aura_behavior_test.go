package audit

import "testing"

func TestAuraSourceBehaviorThresholds(t *testing.T) {
 a:=newAuraAnalysis(Options{})
 for i:=0;i<19;i++ {a.Observe(sourceEvent(i))}
 if len(a.Finish())!=0 {t.Fatal("19 failures must not reach the upstream threshold")}
 a.Observe(sourceEvent(19));out:=a.Finish()
 if len(out)!=1||out[0].RuleID!="brute_force"||out[0].Count!=20 {t.Fatal(out)}
 a=newAuraAnalysis(Options{})
 for i:=0;i<50;i++ {e:=sourceEvent(i*400);e.Status=ptr(404);a.Observe(e)}
 out=a.Finish();if len(out)!=1||out[0].RuleID!="enumeration_404"||out[0].Count!=50 {t.Fatal("404 threshold is case-wide",out)}
}
