use std::{io::{self,Read},fs};
use serde_json::{Value,json};
fn input()->Result<Value,String>{let mut s=String::new();io::stdin().take(32*1024*1024).read_to_string(&mut s).map_err(|e|e.to_string())?;serde_json::from_str(&s).map_err(|e|e.to_string())}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1)}}
fn pipeline(args:&[String])->Result<(),String>{
 let cwd=std::env::current_dir().map_err(|e|e.to_string())?;
 let root=cwd.ancestors().find(|p|p.join("backend/app/cli.py").exists()).ok_or("Run from the JOCKY repository or a child directory")?;
 let python=root.join(if cfg!(windows){".venv/Scripts/python.exe"}else{".venv/bin/python"});
 let status=std::process::Command::new(python).args(["-m","backend.app.cli"]).args(args).current_dir(root).status().map_err(|e|format!("Python pipeline unavailable; run setup first: {e}"))?;
 if !status.success(){return Err("Investigation command failed".into())}Ok(())
}
fn run()->Result<(),String>{let a:Vec<String>=std::env::args().collect();let cmd=a.get(1).map(String::as_str).unwrap_or("help");let result=match cmd {
 "simulate"|"run"|"report"=>{pipeline(&a[1..])?;return Ok(())},
 "check"|"compile"=>{let src=if a.get(2).map(String::as_str)==Some("--stdin"){input()?["source"].as_str().ok_or("Source required")?.to_string()}else{fs::read_to_string(a.get(2).ok_or("Script path required")?).map_err(|e|e.to_string())?};match jocky_language::compile(&src){Ok(p)=>{let out=json!({"ok":true,"plan_digest":jocky_ir::digest(&p),"plan":p,"diagnostics":[]});if let Some(i)=a.iter().position(|s|s=="--output"){let path=a.get(i+1).ok_or("Output path required")?;if let Some(parent)=std::path::Path::new(path).parent(){fs::create_dir_all(parent).map_err(|e|e.to_string())?}fs::write(path,serde_json::to_vec_pretty(&out["plan"]).unwrap()).map_err(|e|e.to_string())?;}out},Err(ds)=>{println!("{}",json!({"ok":false,"diagnostics":ds}));std::process::exit(2)}}},
 "operation"=>jocky_runtime::operation(&input()?)?,
 "seal"=>{let v=input()?;json!(jocky_evidence::seal(v["stream_id"].as_str().ok_or("stream id required")?,v["records"].as_array().ok_or("records required")?.clone(),v["complete"].as_bool().unwrap_or(false)))},
 "verify"=>{let v:Value=if let Some(path)=a.get(2){serde_json::from_str(&fs::read_to_string(path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?}else{input()?};if v.get("streams").is_some(){let mut args=a[1..].to_vec();args[0]="verify-bundle".into();pipeline(&args)?;return Ok(())}let s:jocky_evidence::Stream=serde_json::from_value(v).map_err(|e|e.to_string())?;match jocky_evidence::verify(&s){Ok(())=>json!({"integrity":"valid","completeness":s.completeness}),Err(e)=>json!({"integrity":"invalid","error":e,"completeness":s.completeness})}},
 "analyze"=>{let v=input()?;jocky_analysis::analyze(v["evidence"].as_array().ok_or("evidence required")?,v["detections"].as_array().ok_or("detections required")?)},
 "predicate"=>{let v=input()?;let matches=v["events"].as_array().ok_or("events required")?.iter().map(|e|jocky_detection::evaluate(&v["predicate"],e)).collect::<Result<Vec<_>,_>>()?;json!({"matches":matches})},
 _=>json!({"usage":"jocky check|compile <script> [--output plan.json]; operation|seal|verify|analyze|predicate (JSON stdin)"})};println!("{}",serde_json::to_string(&result).unwrap());Ok(())}
