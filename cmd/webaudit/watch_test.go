package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWatchHelp(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run([]string{"watch", "--help"}, &out, &errout); code != 0 || !strings.Contains(errout.String(), "--from") {
		t.Fatalf("%d %s", code, errout.String())
	}
}

func TestWatchHookArguments(t *testing.T){
 var out,errout bytes.Buffer
 if code:=run([]string{"watch","--help"},&out,&errout);code!=0||!strings.Contains(errout.String(),"on-detect-arg"){t.Fatalf("%d %s",code,errout.String())}
 errout.Reset();if code:=run([]string{"watch","--on-detect-arg=-File","access.log"},&out,&errout);code!=2||!strings.Contains(errout.String(),"preceding --on-detect"){t.Fatalf("%d %s",code,errout.String())}
}
