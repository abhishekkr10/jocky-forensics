use jocky_ir::*;
use serde::{Serialize,Deserialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Diagnostic {pub code:String,pub message:String,pub span:Span}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Token {pub text:String,pub quoted:bool,pub span:Span}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Statement {pub keyword:String,pub tokens:Vec<Token>,pub span:Span}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Ast {pub statements:Vec<Statement>}
fn err(code:&str,msg:impl Into<String>,span:&Span)->Diagnostic{Diagnostic{code:code.into(),message:msg.into(),span:span.clone()}}
pub fn lex(src:&str)->Result<Vec<Token>,Diagnostic>{
 let mut out=vec![]; let mut iter=src.char_indices().peekable(); let(mut line,mut col)=(1,1);
 while let Some((start,c))=iter.next(){let span=Span{start,end:start+c.len_utf8(),line,column:col}; col+=1;
  if c=='#'{while let Some((_,x))=iter.peek(){if *x=='\n'{break} iter.next(); col+=1;} continue}
  if c=='\n'||c==';'{out.push(Token{text:"\n".into(),quoted:false,span});if c=='\n'{line+=1;col=1}continue}
  if c.is_whitespace(){continue}
  if c=='"'{let mut end=start+1;let mut escaped=false;let mut closed=false;
   for (i,x) in iter.by_ref(){col+=1;end=i+x.len_utf8(); if x=='\n'{return Err(err("E001","Newline inside string",&span))} if x=='"'&&!escaped{closed=true;break} if x=='\\'&&!escaped{escaped=true}else{escaped=false}}
   if !closed{return Err(err("E001","Unterminated string",&span))}
   let text=serde_json::from_str::<String>(&src[start..end]).map_err(|_|err("E001","Invalid string escape",&span))?;
   out.push(Token{text,quoted:true,span:Span{end,..span}});continue
  }
  if "[]=,()<>!".contains(c){let mut text=c.to_string();let mut end=span.end;if let Some((i,'='))=iter.peek().copied(){if "=<>!".contains(c){iter.next();text.push('=');end=i+1;col+=1;}}
   out.push(Token{text,quoted:false,span:Span{end,..span}});continue}
  let mut end=span.end;while let Some((i,x))=iter.peek().copied(){if x.is_whitespace()||"[]=,()<>!;#\"".contains(x){break}iter.next();end=i+x.len_utf8();col+=1;}
  out.push(Token{text:src[start..end].into(),quoted:false,span:Span{end,..span}});
 }
 Ok(out)
}
pub fn parse(src:&str)->Result<Ast,Diagnostic>{
 let tokens=lex(src)?;let mut statements=vec![];let mut current:Vec<Token>=vec![];let mut depth=0;
 for t in tokens {if t.text=="["{depth+=1}if t.text=="]"{depth-=1;if depth<0{return Err(err("E002","Unexpected ]",&t.span))}}
  if t.text=="\n"&&depth==0 {
   if !current.is_empty(){
    // Correlation may continue on the following line through its required `as` binding.
    if current[0].text=="correlate"&&!current.iter().any(|x|x.text=="as"){continue}
    let first=current.remove(0);let end=current.last().map(|t|t.span.end).unwrap_or(first.span.end);
    statements.push(Statement{keyword:first.text,tokens:std::mem::take(&mut current),span:Span{end,..first.span}});
   }
  }else if t.text!="\n"{current.push(t)}
 }
 if depth!=0{return Err(err("E002","Unclosed list",&current[0].span))}
 if !current.is_empty(){let first=current.remove(0);let end=current.last().map(|t|t.span.end).unwrap_or(first.span.end);statements.push(Statement{keyword:first.text,tokens:current,span:Span{end,..first.span}})}
 Ok(Ast{statements})
}
struct Cursor<'a>{ts:&'a[Token],i:usize,span:&'a Span}
impl<'a> Cursor<'a>{
 fn take(&mut self)->Result<&'a Token,Diagnostic>{let t=self.ts.get(self.i).ok_or_else(||err("E002","Incomplete statement",self.span))?;self.i+=1;Ok(t)}
 fn word(&mut self,w:&str)->Result<(),Diagnostic>{let t=self.take()?;if t.text!=w||t.quoted{return Err(err("E002",format!("Expected '{w}'"),&t.span))}Ok(())}
 fn text(&mut self)->Result<String,Diagnostic>{Ok(self.take()?.text.clone())}
 fn string(&mut self)->Result<String,Diagnostic>{let t=self.take()?;if !t.quoted{return Err(err("E002","Expected quoted string",&t.span))}Ok(t.text.clone())}
 fn binding(&mut self)->Result<String,Diagnostic>{let t=self.take()?;if t.quoted||!t.text.chars().enumerate().all(|(i,c)|c=='_'||c.is_ascii_alphabetic()||(i>0&&c.is_ascii_digit())){return Err(err("E002","Invalid identifier",&t.span))}Ok(t.text.clone())}
 fn list(&mut self,quoted:bool)->Result<Vec<String>,Diagnostic>{self.word("[")?;let mut xs=vec![];loop{xs.push(if quoted{self.string()?}else{self.binding()?});let sep=self.text()?;if sep=="]"{break}if sep!=","{return Err(err("E002","Expected comma or ]",self.span))}}Ok(xs)}
 fn done(&self)->Result<(),Diagnostic>{if self.i!=self.ts.len(){Err(err("E002","Unexpected trailing tokens",&self.ts[self.i].span))}else{Ok(())}}
}
pub fn compile(src:&str)->Result<Plan,Vec<Diagnostic>>{
 if src.len()>65536{return Err(vec![err("E000","Script exceeds 64 KiB",&Span{start:0,end:0,line:1,column:1})])}
 let ast=parse(src).map_err(|e|vec![e])?;
 lower(src,&ast).map_err(|e|vec![e])
}
fn lower(src:&str,ast:&Ast)->Result<Plan,Diagnostic>{
 let mut p=Plan{ir_version:"1.0".into(),language_version:"0.1".into(),compiler_version:"0.1.0".into(),source_sha256:hash(src.as_bytes()),mode:"live".into(),target_selector:vec!["host".into()],nodes:vec![],rule_packs:vec![],rule_digests:BTreeMap::new(),profiles:vec![],required_capabilities:vec![],limits:BTreeMap::from([("max_records".into(),10000),("max_bytes".into(),10485760),("timeout_seconds".into(),30)]),source_map:BTreeMap::new()};
 let mut symbols:BTreeMap<String,(String,String)>=BTreeMap::new();let mut had_mode=false;let mut had_target=false;
 for s in &ast.statements {let mut c=Cursor{ts:&s.tokens,i:0,span:&s.span};let mut params=BTreeMap::new();let mut inputs=vec![];let mut output=None;let mut typ="unit".to_string();
  match s.keyword.as_str(){
   "mode"=>{if had_mode||!p.nodes.is_empty(){return Err(err("E101","mode must occur once before operations",&s.span))}p.mode=c.text()?;if !["live","lab"].contains(&p.mode.as_str()){return Err(err("E101","mode must be live or lab",&s.span))}had_mode=true;c.done()?;continue},
   "target"=>{if had_target||!p.nodes.is_empty(){return Err(err("E101","target must occur once before operations",&s.span))}p.target_selector=if c.ts.get(c.i).map(|t|t.text.as_str())==Some("["){c.list(true)?}else{vec![c.text()?]};had_target=true;c.done()?;continue},
   "collect"|"simulate"|"import"=>{let name=c.binding()?;params.insert("name".into(),json!(name));
    if s.keyword=="collect"{typ=match name.as_str(){"system_information"=>"system","processes"=>"process_snapshot","network_connections"=>"network","startup_items"=>"startup","files"=>"files","event_logs"=>"events",_=>return Err(err("E102",format!("Unknown collector '{name}'. Did you mean 'processes'?"),&s.span))}.into();p.required_capabilities.push(name.clone());}
    else if s.keyword=="simulate"{if p.mode!="lab"{return Err(err("E150","simulate requires mode lab",&s.span))}if !["process_injection","encoded_script","suspicious_dns","unusual_parent_child_process","vulnerable_driver","api_unhooking","suspicious_lotl","persistence_artifact"].contains(&name.as_str()){return Err(err("E151","Unknown lab event template",&s.span))}typ="events".into();}
    else {if name!="json"{return Err(err("E152","Only JSON import is supported",&s.span))}params.insert("path".into(),json!(c.string()?));typ="events".into();}
    while c.ts.get(c.i).map(|t|t.text.as_str())!=Some("as"){let k=c.binding()?;c.word("=")?;let t=c.take()?;let v=if t.quoted{json!(t.text)}else if let Ok(n)=t.text.parse::<u64>(){json!(n)}else{json!(t.text)};if params.insert(k,v).is_some(){return Err(err("E103","Duplicate argument",&s.span))}}
    c.word("as")?;output=Some(c.binding()?);
    for (k,v) in &params {if k=="name"||k=="path"{continue}if !["root","max_files","profile","since","max_records"].contains(&k.as_str()){return Err(err("E103",format!("Unknown argument '{k}'"),&s.span))}if k.starts_with("max_")&&v.as_u64().filter(|n|*n>0&&*n<=10000).is_none(){return Err(err("E104","Limit must be an integer between 1 and 10000",&s.span))}}
   },
   "hunt"|"scan"=>{c.word(if s.keyword=="hunt"{"sigma"}else{"yara"})?;let pack=c.string()?;if pack!=if s.keyword=="hunt"{"triage-v1"}else{"demo-v1"}{return Err(err("E240","Unknown pinned rule pack",&s.span))}params.insert("pack".into(),json!(pack));p.rule_packs.push(pack);c.word("on")?;inputs.push(c.binding()?);c.word("as")?;output=Some(c.binding()?);typ="detections".into();},
   "correlate"=>{inputs=c.list(false)?;c.word("using")?;let profile=c.string()?;if profile!="triage-v1"{return Err(err("E250","Unknown correlation profile",&s.span))}p.profiles.push(profile.clone());params.insert("profile".into(),json!(profile));c.word("within")?;let d=c.text()?;let secs=duration(&d).ok_or_else(||err("E104","Invalid duration",&s.span))?;params.insert("window_seconds".into(),json!(secs));c.word("as")?;output=Some(c.binding()?);typ="incident".into();},
   "timeline"|"risk"=>{inputs.push(c.binding()?);if s.keyword=="risk"{c.word("using")?;let profile=c.string()?;if profile!="triage-v1"{return Err(err("E250","Unknown risk profile",&s.span))}params.insert("profile".into(),json!(profile));}c.word("as")?;output=Some(c.binding()?);typ=s.keyword.clone();},
   "verify"=>c.word("evidence")?,
   "report"=>{let fmt=c.text()?;if !["html","json"].contains(&fmt.as_str()){return Err(err("E105","Expected html or json",&s.span))}params.insert("format".into(),json!(fmt));params.insert("path".into(),json!(c.string()?));},
   "export"=>{inputs.push(c.binding()?);c.word("json")?;params.insert("path".into(),json!(c.string()?));},
   "compare"=>{inputs.push(c.binding()?);c.word("with")?;inputs.push(c.binding()?);c.word("as")?;output=Some(c.binding()?);typ="comparison".into();},
   "filter"|"assert"=>{inputs.push(c.binding()?);c.word("where")?;let end=if s.keyword=="filter"{c.ts.iter().rposition(|t|!t.quoted&&t.text=="as").ok_or_else(||err("E002","Expected as binding",&s.span))?}else{c.ts.len()};let expression=&c.ts[c.i..end];if expression.len()!=3||!["==","!=","contains"].contains(&expression[1].text.as_str()){return Err(err("E260","This release supports field ==, != or contains literal",&s.span))}params.insert("predicate".into(),json!({"field":expression[0].text,"op":expression[1].text,"value":expression[2].text}));c.i=end;if s.keyword=="filter"{c.word("as")?;output=Some(c.binding()?);typ="filtered".into();}},
   _=>return Err(err("E100",format!("Unknown statement '{}'",s.keyword),&s.span))
  }
  c.done()?;let mut deps=vec![];
  for input in &inputs {let (kind,id)=symbols.get(input).ok_or_else(||err("E201",format!("Dataset '{input}' is not defined"),&s.span))?;deps.push(id.clone());if s.keyword=="hunt"&&kind!="events"{return Err(err("E241","Sigma requires event telemetry, not process snapshots",&s.span))}if s.keyword=="scan"&&kind!="files"{return Err(err("E242","YARA requires a files dataset",&s.span))}if ["timeline","risk"].contains(&s.keyword.as_str())&&kind!="incident"{return Err(err("E243","Expected correlated incident dataset",&s.span))}if s.keyword=="filter"{typ=kind.clone();}}
  let id=format!("op{:03}",p.nodes.len()+1);if let Some(o)=&output {if symbols.insert(o.clone(),(typ.clone(),id.clone())).is_some(){return Err(err("E202",format!("Dataset '{o}' is immutable and already defined"),&s.span))}}
  p.source_map.insert(id.clone(),s.span.clone());p.nodes.push(Node{id,opcode:s.keyword.clone(),placement:if ["collect","simulate","scan","hunt","import","filter"].contains(&s.keyword.as_str()){"endpoint"}else{"coordinator"}.into(),inputs,output,output_type:typ,parameters:params,depends_on:deps,error_policy:"fail".into()});
 }
 p.rule_packs.sort();p.rule_packs.dedup();
 for pack in &p.rule_packs {p.rule_digests.insert(pack.clone(),hash(if pack=="triage-v1" {include_bytes!("../../../rules/sigma/encoded_script.yml")}else{include_bytes!("../../../rules/yara/demo.yar")}));}
 p.profiles.sort();p.profiles.dedup();p.required_capabilities.sort();p.required_capabilities.dedup();
 p.validate().map_err(|e|err("E300",e,&Span{start:0,end:0,line:1,column:1}))?;Ok(p)
}
pub fn duration(s:&str)->Option<u64>{let (n,u)=s.split_at(s.len().checked_sub(1)?);let v=n.parse::<u64>().ok()?;v.checked_mul(match u{"s"=>1,"m"=>60,"h"=>3600,"d"=>86400,_=>return None})}
#[cfg(test)] mod tests{use super::*;
 #[test]fn spans(){let t=lex("# hi\ncollect files root=\"a b\" as f").unwrap();assert_eq!(t[1].span.line,2);assert!(t.iter().any(|t|t.quoted&&t.text=="a b"));}
 #[test]fn deterministic(){let s="mode lab\ncollect processes as p\n";assert_eq!(digest(&compile(s).unwrap()),digest(&compile(s).unwrap()));}
 #[test]fn undefined(){assert_eq!(compile("hunt sigma \"triage-v1\" on missing as h").unwrap_err()[0].code,"E201");}
 #[test]fn wrong_capability(){assert_eq!(compile("collect processes as p\nhunt sigma \"triage-v1\" on p as h").unwrap_err()[0].code,"E241");}
 #[test]fn rejects_shell(){assert!(compile("shell \"whoami\"").is_err());}
 #[test]fn simulation_live_denied(){assert!(compile("simulate process_injection as x").is_err());}
 #[test]fn malformed(){for s in ["target [", "collect", "collect files root=\"bad", "mode lab trailing"]{assert!(compile(s).is_err(),"{s}");}}
 #[test]fn multiline(){assert!(compile("collect processes as p\ncorrelate [p]\n using \"triage-v1\" within 15m as i").is_ok());}
}
