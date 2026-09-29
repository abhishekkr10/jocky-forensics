use jocky_ir::Plan;
use serde_json::Value;
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
pub fn verify_job(request:&Value,plan:&Plan)->Result<(),String>{
 let trusted=std::env::var("JOCKY_AGENT_PUBLIC_KEY").map_err(|_|"Agent trust key is not configured")?;
 let raw=hex::decode(trusted).map_err(|_|"Invalid trust key")?;
 let key=VerifyingKey::from_bytes(&raw.try_into().map_err(|_|"Invalid key length")?).map_err(|e|e.to_string())?;
 let job=&request["signed_job"];let body=&job["body"];
 let sig=hex::decode(job["signature"].as_str().ok_or("Missing job signature")?).map_err(|e|e.to_string())?;
 key.verify(&jocky_ir::canonical(body),&Signature::from_slice(&sig).map_err(|e|e.to_string())?).map_err(|_|"Invalid job signature")?;
 let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs();
 if body["expires_at"].as_u64().unwrap_or(0)<now || body["issued_at"].as_u64().unwrap_or(u64::MAX)>now+30{return Err("Expired or future job".into())}
 if body["plan_digest"]!=jocky_ir::digest(plan)||body["operation_id"]!=request["operation_id"]||body["approved_root"]!=request["approved_root"]{return Err("Signed job binding mismatch".into())}
 Ok(())
}
pub fn validate_source_plan(source:&str,plan:&Plan)->Result<(),String>{plan.validate()?;let expected=jocky_language::compile(source).map_err(|e|format!("{e:?}"))?;if jocky_ir::digest(&expected)!=jocky_ir::digest(plan){return Err("Plan differs from compiler output".into())}Ok(())}
pub fn operation(request:&Value)->Result<Value,String>{let source=request["source"].as_str().ok_or("source required")?;let p:Plan=serde_json::from_value(request["plan"].clone()).map_err(|e|e.to_string())?;validate_source_plan(source,&p)?;verify_job(request,&p)?;let id=request["operation_id"].as_str().ok_or("operation_id required")?;let node=p.nodes.iter().find(|n|n.id==id).ok_or("Unknown operation")?;if node.opcode!="collect"{return Err("Native operation accepts only collection".into())}if p.mode!="live"{return Err("Live collectors require live mode".into())}let root=request["approved_root"].as_str().ok_or("Approved root required")?;jocky_collectors::collect(node.parameters["name"].as_str().ok_or("collector name required")?,&serde_json::to_value(&node.parameters).unwrap(),std::path::Path::new(root))}
