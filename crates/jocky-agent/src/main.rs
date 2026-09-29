use std::io::{self,Read};
fn main(){let mut s=String::new();let result=io::stdin().take(1024*1024).read_to_string(&mut s).map_err(|e|e.to_string()).and_then(|_|serde_json::from_str(&s).map_err(|e|e.to_string())).and_then(|v|jocky_runtime::operation(&v));match result{Ok(v)=>println!("{v}"),Err(e)=>{eprintln!("{e}");std::process::exit(1)}}}
