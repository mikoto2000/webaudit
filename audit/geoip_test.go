package audit

import (
 "bytes"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "testing"
 "time"
)

func testGeo(t *testing.T, capacity int) *GeoIP {
 t.Helper()
 g, err := OpenGeoIP("testdata/geoip/country.mmdb", "testdata/geoip/asn.mmdb", "", capacity)
 if err != nil { t.Fatal(err) }; t.Cleanup(func(){g.Close()}); return g
}
func TestGeoIPLookup(t *testing.T) {
 g := testGeo(t, 4)
 for _, ip := range []string{"8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"} {
  x := g.Lookup(ip)
  if x.Classification != "public" || val(x.CountryCode) != "US" || val(x.CountryName) != "Example Country" || val(x.ASN) != 64500 || val(x.ASNOrganization) != "Example Network" {t.Fatalf("%s: %+v", ip,x)}
 }
 x := g.Lookup("1.1.1.1")
 if x.CountryCode != nil || x.ASN != nil || x.Classification != "public" {t.Fatal(x)}
 for ip,want := range map[string]string{"10.0.0.1":"private", "fc00::1":"private", "127.0.0.1":"loopback", "::1":"loopback", "169.254.1.1":"link_local", "fe80::1":"link_local", "192.0.2.1":"reserved", "2001:db8::1":"reserved", "100.64.0.1":"shared", "224.0.0.1":"multicast", "ff02::1":"multicast", "0.0.0.0":"unspecified", "::":"unspecified", "240.0.0.1":"reserved", "bad":"invalid"} {
  before:=g.lookups; x:=g.Lookup(ip)
  if x.Classification != want || x.CountryCode != nil || x.ASN != nil || g.lookups != before {t.Fatalf("%s: %+v",ip,x)}
 }
 if len(g.Metadata())!=2 || val(g.Metadata()[0].UpdatedAt)!="2026-11-01" || g.Metadata()[0].Provider!="DB-IP" {t.Fatal(g.Metadata())}
}
func TestGeoIPBoundedCache(t *testing.T) {
 g:=testGeo(t,2)
 g.Lookup("8.8.8.8"); before:=g.lookups
 for i:=0;i<100;i++ {g.Lookup("8.8.8.8")}
 if g.lookups != before {t.Fatal("repeated lookup hit MMDB")}
 g.Lookup("1.1.1.1"); before=g.lookups; g.Lookup("1.1.1.1")
 if g.lookups!=before {t.Fatal("negative result not cached")}
 for i:=1;i<255;i++ {g.Lookup(fmt.Sprintf("9.9.9.%d",i))}
 if g.cache.Len()!=2 || len(g.entries)!=2 {t.Fatal("unbounded cache")}
}
func TestGeoIPDiscoveryErrors(t *testing.T) {
 dir:=t.TempDir()
 g,err:=OpenGeoIP("","",dir,4)
 if err!=nil || g!=nil {t.Fatalf("absent DB: %v %v",g,err)}
 if _,err=OpenGeoIP(filepath.Join(dir,"missing"),"",dir,4);err==nil {t.Fatal("missing explicit DB accepted")}
 os.WriteFile(filepath.Join(dir,"country.mmdb"),[]byte("broken"),0600)
 if _,err=OpenGeoIP(filepath.Join(dir,"country.mmdb"),"",dir,4);err==nil {t.Fatal("corrupt explicit DB accepted")}
 b,_:=os.ReadFile("testdata/geoip/country.mmdb"); os.WriteFile(filepath.Join(dir,"country.mmdb"),b,0600)
 g,err=OpenGeoIP("","",dir,4)
 if err!=nil || g==nil {t.Fatal(err)}; g.Close()
 // An explicit nonexistent path must not silently fall back to a valid auto DB.
 if _,err=OpenGeoIP(filepath.Join(dir,"missing"),"",dir,4);err==nil {t.Fatal("explicit override ignored")}
}
func TestGeoIPIntegrationAndNoRiskIncrease(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"access.log")
 var lines strings.Builder
 for _,ip:=range []string{"8.8.8.8","8.8.8.9","2606:4700::1111","1.1.1.1","10.0.0.1"} {
  for i:=0;i<3;i++ {fmt.Fprintf(&lines,"%s - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0\n",ip)}
 }
 os.WriteFile(path,[]byte(lines.String()),0600)
 now:=func()time.Time{return time.Unix(0,0)}
 plain:=Analyze([]string{path},Options{Now:now})
 g:=testGeo(t,4)
 enriched:=Analyze([]string{path},Options{Now:now,GeoIP:g})
 if enriched.GeoIP==nil || len(enriched.GeoIP.Countries)!=2 || len(enriched.GeoIP.ASNs)!=2 {t.Fatalf("%+v",enriched.GeoIP)}
 var asn GeoGroup
 for _,a:=range enriched.GeoIP.ASNs {if a.Key=="64500" {asn=a}}
 if asn.Requests!=9 || asn.Incidents!=3 || len(asn.IPs)!=3 || !asn.MultiIP || len(asn.Categories)==0 {t.Fatalf("%+v",asn)}
 if len(enriched.Findings)!=len(plain.Findings) {t.Fatal("geo created incidents")}
 for i,f:=range enriched.Findings {
  if f.GeoIP==nil {t.Fatal("missing incident enrichment")}
  f.GeoIP=nil
  if !reflect.DeepEqual(f,plain.Findings[i]) {t.Fatalf("GeoIP changed detection: %+v / %+v",f,plain.Findings[i])}
 }
 // Optional fields must disappear completely to preserve disabled serialization.
 b,_:=json.Marshal(plain); if strings.Contains(string(b),`"geoip"`) {t.Fatal("disabled output changed")}
 for _,format:=range []string{"summary","json","csv","html"} {
  var out bytes.Buffer
  if err:=WriteReport(&out,enriched,format);err!=nil {t.Fatal(err)}
  if !strings.Contains(out.String(),"DB-IP") || !strings.Contains(out.String(),"64500") || !strings.Contains(out.String(),"2026-11-01") {t.Fatalf("missing GeoIP in %s",format)}
 }
}
