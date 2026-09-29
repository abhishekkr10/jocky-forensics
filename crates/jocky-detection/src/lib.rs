use serde_json::Value;
pub fn field<'a>(v:&'a Value,path:&str)->Option<&'a Value>{let mut cur=v;for p in path.split('.') {cur=cur.get(p)?}Some(cur)}
pub fn evaluate(p:&Value,event:&Value)->Result<bool,String>{
 let op=p["op"].as_str().ok_or("Missing predicate opcode")?;
 match op {
 "and"|"or"=>{let xs=p["args"].as_array().ok_or("Missing predicate arguments")?;let results=xs.iter().map(|x|evaluate(x,event)).collect::<Result<Vec<_>,_>>()?;Ok(if op=="and"{results.iter().all(|x|*x)}else{results.iter().any(|x|*x)})},
 "not"=>Ok(!evaluate(&p["arg"],event)?),
 "eq"|"contains"|"startswith"|"endswith"|"wildcard"=>{let path=p["field"].as_str().ok_or("Missing field")?;let Some(actual)=field(event,path) else{return Ok(p["value"].is_null()&&op=="eq")};let expected=&p["value"];
 if expected.is_null(){return Ok(actual.is_null()&&op=="eq")}
 if !actual.is_string()||!expected.is_string(){return Ok(op=="eq"&&actual==expected)}
 let a=actual.as_str().unwrap().to_lowercase();let b=expected.as_str().unwrap().to_lowercase();Ok(match op{"eq"=>a==b,"contains"=>a.contains(&b),"startswith"=>a.starts_with(&b),"endswith"=>a.ends_with(&b),_=>wildcard(&a,&b)})},
 _=>Err(format!("Unsupported predicate {op}"))
 }
}
fn wildcard(a:&str,b:&str)->bool{let a:Vec<char>=a.chars().collect();let b:Vec<char>=b.chars().collect();let(mut i,mut j,mut star,mut mark)=(0,0,None,0);while i<a.len(){if j<b.len()&&(b[j]=='?'||b[j]==a[i]){i+=1;j+=1}else if j<b.len()&&b[j]=='*'{star=Some(j);j+=1;mark=i}else if let Some(s)=star{mark+=1;i=mark;j=s+1}else{return false}}while j<b.len()&&b[j]=='*'{j+=1}j==b.len()}
#[cfg(test)]mod tests{use super::*;use serde_json::json;
 #[test]fn predicates(){assert!(evaluate(&json!({"op":"contains","field":"CommandLine","value":"-encodedcommand"}),&json!({"CommandLine":"pwsh -EncodedCommand harmless"})).unwrap());assert!(!evaluate(&json!({"op":"eq","field":"missing","value":"x"}),&json!({})).unwrap());}
 #[test]fn reject_unknown(){assert!(evaluate(&json!({"op":"regex"}),&json!({})).is_err())}
 #[test]fn glob(){assert!(wildcard("powershell.exe","*shell.?xe"));assert!(!wildcard("cmd.exe","*shell*"))}
}
