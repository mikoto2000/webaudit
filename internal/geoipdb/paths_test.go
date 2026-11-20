package geoipdb
import("strings";"testing")
func TestResolveDir(t *testing.T){for _,tc:=range []struct{os,xdg,home,local,want string;bad bool}{
 {"linux","/data/日本 語","/home/u","","/data/日本 語/webaudit/geoip",false},
 {"linux","","/home/u","","/home/u/.local/share/webaudit/geoip",false},
 {"linux","relative","/home/u","","/home/u/.local/share/webaudit/geoip",false},
 {"linux","","","","",true},
 {"windows",`C:\Users\日本 語\data`,"",`C:\local`,`C:\Users\日本 語\data\webaudit\geoip`,false},
 {"windows","","",`C:\local`,`C:\local\webaudit\geoip`,false},
 {"windows","relative","",`C:\local`,`C:\local\webaudit\geoip`,false},
 {"windows","","","","",true},
 {"windows",`C:relative`,"","","",true},
 }{t.Run(tc.os+tc.xdg+tc.home,func(t *testing.T){env:=map[string]string{"XDG_DATA_HOME":tc.xdg,"HOME":tc.home,"LOCALAPPDATA":tc.local};got,err:=ResolveDir(tc.os,func(k string)string{return env[k]});if (err!=nil)!=tc.bad||!strings.EqualFold(got,tc.want){t.Fatalf("got %q %v; want %q",got,err,tc.want)}})}}
