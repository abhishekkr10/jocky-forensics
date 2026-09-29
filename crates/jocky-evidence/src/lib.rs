use jocky_ir::{digest,hash};
use serde::{Serialize,Deserialize};
use serde_json::{Value,json};
#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Entry {pub sequence:u64,pub record:Value,pub record_digest:String,pub previous_hash:String,pub current_hash:String}
#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Stream {pub stream_id:String,pub entries:Vec<Entry>,pub record_count:usize,pub chain_head:String,pub completeness:String}
pub fn seal(id:&str,records:Vec<Value>,complete:bool)->Stream{
 let mut prev=hash(format!("JOCKY:stream:v1:{id}").as_bytes());let mut entries=vec![];
 for (i,record) in records.into_iter().enumerate(){let rd=digest(&record);let current=digest(&json!(["JOCKY:entry:v1",id,i+1,prev,rd]));entries.push(Entry{sequence:(i+1)as u64,record,record_digest:rd,previous_hash:prev,current_hash:current.clone()});prev=current;}
 Stream{stream_id:id.into(),record_count:entries.len(),entries,chain_head:prev,completeness:if complete{"complete"}else{"partial"}.into()}
}
pub fn verify(s:&Stream)->Result<(),String>{
 if s.record_count!=s.entries.len(){return Err("Record count mismatch (possible truncation)".into())}
 let mut prev=hash(format!("JOCKY:stream:v1:{}",s.stream_id).as_bytes());
 for (i,e) in s.entries.iter().enumerate(){let expected=digest(&json!(["JOCKY:entry:v1",s.stream_id,i+1,prev,digest(&e.record)]));if e.sequence!=(i+1)as u64||e.record_digest!=digest(&e.record)||e.previous_hash!=prev||e.current_hash!=expected{return Err(format!("Broken chain at position {}",i+1))}prev=e.current_hash.clone();}
 if prev!=s.chain_head{return Err("Incorrect chain head".into())}Ok(())
}
#[cfg(test)]mod tests{use super::*;fn fixture()->Stream{seal("s",vec![json!({"a":1}),json!({"a":2}),json!({"a":3})],true)}
 #[test]fn valid(){assert!(verify(&fixture()).is_ok())}
 #[test]fn tampering(){for mode in 0..5{let mut s=fixture();match mode{0=>s.entries[0].record["a"]=json!(9),1=>{s.entries.remove(1);},2=>{s.entries.pop();},3=>s.entries.swap(0,1),_=>s.chain_head="bad".into()};assert!(verify(&s).is_err())}}
}
