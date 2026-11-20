package audit

import (
 "bytes"
 "compress/gzip"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestLogEscapeNormalization(t *testing.T){h,n:=Detect(Event{Target:`/?q=\x3cscript\x3e`});if len(h)==0||len(n.Steps)==0{t.Fatal("missing Nginx/Apache escaped payload",n)}}
func TestRetentionBounds(t *testing.T){
 e:=incidentEvent(0,200);e.Target="/.env?padding="+strings.Repeat("x",60000);e.Path="/.env";e.Raw=e.Target;e.UA=ptr(strings.Repeat("u",50000));h,n:=Detect(e);c:=NewCorrelator(Options{});c.Add(e,h,n);f:=c.Finish();if len(f)!=1{t.Fatal("missing")};ev:=f[0].Evidence[0];if len(ev.Event.Raw)>4096||len(ev.Normalization.Original)>4096||!ev.Event.EvidenceTruncated{t.Fatal("unbounded evidence retention")}
}
func TestUnrecognizedInputIsPartial(t *testing.T){p:=filepath.Join(t.TempDir(),"a.log");_=os.WriteFile(p,[]byte("garbage\n"),0600);r:=Analyze([]string{p},Options{});if !r.Partial||r.Unparsed!=1{t.Fatal(r)}}
type brokenWriter struct{}
func(brokenWriter)Write([]byte)(int,error){return 0,io.ErrClosedPipe}
func TestSummaryWriteErrors(t *testing.T){if WriteReport(brokenWriter{},Report{},"summary")==nil{t.Fatal("lost write error")}}
func TestGzipCRCAndBombLimit(t *testing.T){d:=t.TempDir();var b bytes.Buffer;z:=gzip.NewWriter(&b);for i:=0;i<100;i++{fmt.Fprintln(z,common)};_=z.Close();p:=filepath.Join(d,"a.gz");_=os.WriteFile(p,b.Bytes(),0600);r:=Stream([]string{p},Options{MaxFileBytes:500},func(Event){});if !r.Partial{t.Fatal("gzip limit bypass")};data:=b.Bytes();data[len(data)-5]^=255;_=os.WriteFile(p,data,0600);r=Stream([]string{p},Options{},func(Event){});if !r.Partial{t.Fatal("gzip corruption ignored")}}
func FuzzParse(f *testing.F){f.Add(common);f.Add(`{"remote_addr":"127.0.0.1"}`);f.Fuzz(func(t *testing.T,s string){if len(s)>65536{return};_,_=Parse(s,"fuzz",1,"");n:=Normalize(s);if len(n.Variants)>7||n.Original!=s{t.Fatal(n)}})}
func BenchmarkAnalyzeRequest(b *testing.B){e:=sample(0);e.Target="/api/orders?sort=price&page=2";b.ReportAllocs();for i:=0;i<b.N;i++{Detect(e)}}
