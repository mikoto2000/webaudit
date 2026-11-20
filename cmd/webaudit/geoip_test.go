package main
import("bytes";"os";"path/filepath";"strings";"testing")
func TestGeoIPManagementCLI(t *testing.T){t.Setenv("XDG_DATA_HOME",t.TempDir());var out,err bytes.Buffer
 if code:=run([]string{"geoip","status"},&out,&err);code!=0||!strings.Contains(out.String(),"Not installed"){t.Fatalf("%d %s %s",code,out.String(),err.String())}
 for _,args:=range [][]string{{"geoip"},{"geoip","other"},{"geoip","status","extra"}} {out.Reset();err.Reset();if run(args,&out,&err)!=2{t.Fatal(args)}}
 d:=filepath.Join(os.Getenv("XDG_DATA_HOME"),"webaudit","geoip");os.MkdirAll(d,0700);os.WriteFile(filepath.Join(d,"metadata.json"),[]byte("broken"),0600);out.Reset();err.Reset();if run([]string{"geoip","status"},&out,&err)!=1||!strings.Contains(err.String(),"corrupt"){t.Fatal(out.String(),err.String())}
}
