package watch
import("context";"os";"path/filepath";"reflect";"testing";"time")
func TestStateRestartPartialAndRotation(t *testing.T){
 t.Setenv("XDG_STATE_HOME",t.TempDir());p:=filepath.Join(t.TempDir(),"access.log");put(t,p,"first\npar")
 r,err:=NewReader([]string{p},ReaderOptions{Beginning:true});if err!=nil{t.Fatal(err)};poll(t,r)
 e:=NewEngine(EngineOptions{});now:=time.Now();e.Observe(event(t,0,404,"/.env"),now);first:=e.Flush(now)
 store,err:=OpenStore(r.Targets,"test",false);if err!=nil{t.Fatal(err)}
 if _,err=OpenStore(r.Targets,"test",false);err==nil{t.Fatal("concurrent store permitted")}
 if err=store.Save(Capture(r,e,nil));err!=nil{t.Fatal(err)};store.Close();r.Close()
 if err=os.Rename(p,p+".1");err!=nil{t.Fatal(err)};appendLog(t,p+".1","tial\n");put(t,p,"new\n")
 store,err=OpenStore([]string{p},"test",false);if err!=nil{t.Fatal(err)};defer store.Close();saved,err:=store.Load();if err!=nil{t.Fatal(err)}
 r,err=NewReader([]string{p},ReaderOptions{});if err!=nil{t.Fatal(err)};defer r.Close();e=NewEngine(EngineOptions{})
 if err=Restore(r,e,saved);err!=nil{t.Fatal(err)};if got:=poll(t,r);!reflect.DeepEqual(got,[]string{"partial","new"}){t.Fatal(got)}
 if got:=e.Flush(now);len(got)!=0{t.Fatal("restart duplicate",got)};e.Observe(event(t,1,200,"/.env"),now);got:=e.Flush(now);if len(got)!=1||got[0].IncidentID!=first[0].IncidentID||got[0].Revision!=2{t.Fatal(got)}
}
func TestStateCorruptionResetAndAtomic(t *testing.T){
 t.Setenv("XDG_STATE_HOME",t.TempDir());targets:=[]string{filepath.Join(t.TempDir(),"access.log")};s,err:=OpenStore(targets,"x",false);if err!=nil{t.Fatal(err)}
 put(t,s.Path,`{"incomplete":`);if _,err=s.Load();err==nil{t.Fatal("corrupt state accepted")};s.Close()
 s,err=OpenStore(targets,"x",true);if err!=nil{t.Fatal(err)};defer s.Close();if v,err:=s.Load();err!=nil||v!=nil{t.Fatal(v,err)}
 e:=NewEngine(EngineOptions{});r,err:=NewReader(targets,ReaderOptions{});if err!=nil{t.Fatal(err)};defer r.Close();state:=Capture(r,e,map[string]uint64{"hook":1})
 if err=s.Save(state);err!=nil{t.Fatal(err)};before,_:=os.ReadFile(s.Path)
 state.Cursors=[]Cursor{{Offset:-1}};if err=s.Save(state);err==nil{t.Fatal("invalid offset accepted")};after,_:=os.ReadFile(s.Path);if !reflect.DeepEqual(before,after){t.Fatal("old state replaced")}
 state=Capture(r,e,nil);state.Engine.Sequence=9;if err=s.Save(state);err!=nil{t.Fatal(err)};v,err:=s.Load();if err!=nil||v.Engine.Sequence!=9{t.Fatal(v,err)}
 _=context.Background()
}
