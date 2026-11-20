package geoipdb
import("context";"fmt";"io";"net/http";"strings";"testing";"time")
type roundTripFunc func(*http.Request)(*http.Response,error)
func(f roundTripFunc)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
func page(role,version,sha string)string{return fmt.Sprintf(`<dl><dt>Format</dt><dd>MMDB</dd><dt>Release</dt><dd>%s</dd><dt>SHA1SUM</dt><dd class="small">%s</dd></dl><a href='https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz'>Download</a>`,mustMonth(version),sha,role,version)}
func mustMonth(v string)string{t,_:=time.Parse("2006-01",v);return t.Format("January 2006")}
func TestOfficialReleaseDiscovery(t *testing.T){
 p:=NewProvider();p.client.Transport=roundTripFunc(func(r *http.Request)(*http.Response,error){return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader(page("country","2026-11",strings.Repeat("a",40)))),Header:http.Header{}},nil})
 r,err:=p.Latest(context.Background(),"country");if err!=nil||r.Version!="2026-11"||r.SHA1!=strings.Repeat("a",40){t.Fatal(r,err)}
 for _,body:=range []string{"page changed",strings.Replace(page("country","2026-11",strings.Repeat("a",40)),"download.db-ip.com","evil.test",1),strings.Replace(page("country","2026-11",strings.Repeat("a",40)),"November 2026","October 2026",1)}{if _,err:=parseRelease([]byte(body),"country");err==nil{t.Fatal("unsafe/changed page accepted")}}
}
func TestRestrictedHTTPS(t *testing.T){p:=NewProvider();for _,raw:=range []string{"http://db-ip.com/db/lite.php","https://evil.test/free/x","https://user@db-ip.com/db/lite.php","https://download.db-ip.com/free/../../x","https://db-ip.com:444/db/lite.php"}{if err:=allowedURL(raw);err==nil{t.Fatal(raw)}}
 if err:=p.client.CheckRedirect(&http.Request{URL:mustURL("https://evil.test/x")},nil);err==nil{t.Fatal("redirect escaped allowlist")}
 if err:=p.client.CheckRedirect(&http.Request{URL:mustURL("https://db-ip.com/db/download/ip-to-country-lite")},nil);err!=nil{t.Fatal(err)}
 for _,code:=range []int{404,500}{p.client.Transport=roundTripFunc(func(r *http.Request)(*http.Response,error){return &http.Response{StatusCode:code,Body:io.NopCloser(strings.NewReader("error"))},nil});if _,err:=p.Latest(context.Background(),"country");err==nil{t.Fatal(code)}}
 p.maxPage=10;p.client.Transport=roundTripFunc(func(r *http.Request)(*http.Response,error){return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader(strings.Repeat("x",11)))},nil});if _,err:=p.Latest(context.Background(),"country");err==nil{t.Fatal("oversize page")}
 p.client.Transport=roundTripFunc(func(r *http.Request)(*http.Response,error){<-r.Context().Done();return nil,r.Context().Err()});ctx,cancel:=context.WithTimeout(context.Background(),time.Millisecond);defer cancel();if _,err:=p.Latest(ctx,"country");err==nil{t.Fatal("timeout ignored")}
}
