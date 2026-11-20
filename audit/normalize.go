package audit

import (
 "strings"
 "unicode/utf8"
)
type Normalized struct {Original string `json:"original"`; Variants []string `json:"variants"`; Steps []string `json:"steps"`; Warnings []string `json:"warnings"`}
// Normalize preserves raw data and emits heuristic detection variants, not a
// claim about how an unknown application decodes or canonicalizes its URLs.
func Normalize(s string)Normalized{
 n:=Normalized{Original:s,Variants:[]string{s}}
 add:=func(v string){for _,x:=range n.Variants{if x==v{return}};if len(n.Variants)<7{n.Variants=append(n.Variants,v)}}
 cur:=s
 for depth:=0;depth<2;depth++{
  next,bad:=percentDecode(cur);if bad{n.Warnings=append(n.Warnings,"Invalid percent encoding preserved")};if next==cur{break};n.Steps=append(n.Steps,"percent-decode detection variant");add(next);cur=next
 }
 base:=append([]string(nil),n.Variants...)
 for _,v:=range base{
  x:=strings.ToLower(strings.ReplaceAll(v,`\`,"/"));if x!=v{n.Steps=append(n.Steps,"case-fold/backslash detection variant")};if i:=strings.IndexByte(x,'?');i>=0&&strings.Contains(x[i:],"+"){x=x[:i]+strings.ReplaceAll(x[i:],"+"," ");n.Steps=append(n.Steps,"query plus-to-space detection variant")};add(x)
 }
 if !utf8.ValidString(cur){n.Warnings=append(n.Warnings,"Decoded bytes are not valid UTF-8; no Unicode repair inferred")}
 if strings.Contains(strings.ToLower(s),"%u"){n.Warnings=append(n.Warnings,"Nonstandard %u encoding is not decoded")}
 if strings.Contains(cur,"%25"){n.Warnings=append(n.Warnings,"Maximum decode depth is two")}
 return n
}
func percentDecode(s string)(string,bool){
 b:=make([]byte,0,len(s));bad:=false
 hex:=func(c byte)int{if c>='0'&&c<='9'{return int(c-'0')};if c>='a'&&c<='f'{return int(c-'a')+10};if c>='A'&&c<='F'{return int(c-'A')+10};return -1}
 for i:=0;i<len(s);i++{if s[i]=='%' {if i+2<len(s)&&hex(s[i+1])>=0&&hex(s[i+2])>=0{b=append(b,byte(hex(s[i+1])*16+hex(s[i+2])));i+=2;continue};bad=true};b=append(b,s[i])};return string(b),bad
}
