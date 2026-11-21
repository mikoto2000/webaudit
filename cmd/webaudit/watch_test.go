package main

import("bytes";"strings";"testing")
func TestWatchHelp(t *testing.T){var out,errout bytes.Buffer;if code:=run([]string{"watch","--help"},&out,&errout);code!=0||!strings.Contains(errout.String(),"--from"){t.Fatalf("%d %s",code,errout.String())}}
