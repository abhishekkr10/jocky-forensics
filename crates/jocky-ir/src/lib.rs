use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn hash(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
pub fn canonical(v: &Value) -> Vec<u8> { serde_json::to_vec(v).expect("JSON value") }
pub fn digest<T: Serialize>(v: &T) -> String { hash(&canonical(&serde_json::to_value(v).unwrap())) }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Span { pub start: usize, pub end: usize, pub line: usize, pub column: usize }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
 pub id: String, pub opcode: String, pub placement: String,
 pub inputs: Vec<String>, pub output: Option<String>, pub output_type: String,
 pub parameters: BTreeMap<String, Value>, pub depends_on: Vec<String>, pub error_policy: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
 pub ir_version: String, pub language_version: String, pub compiler_version: String,
 pub source_sha256: String, pub mode: String, pub target_selector: Vec<String>,
 pub nodes: Vec<Node>, pub rule_packs: Vec<String>, pub rule_digests: BTreeMap<String,String>, pub profiles: Vec<String>,
 pub required_capabilities: Vec<String>, pub limits: BTreeMap<String,u64>, pub source_map: BTreeMap<String,Span>,
}
pub const OPCODES: &[&str] = &["collect","simulate","import","filter","hunt","scan","correlate","timeline","risk","verify","report","export","compare","assert"];
impl Plan {
 pub fn validate(&self) -> Result<(),String> {
  if self.ir_version!="1.0" || !["live","lab"].contains(&self.mode.as_str()) { return Err("Unsupported IR version or mode".into()) }
  if self.nodes.len()>256 || self.target_selector.is_empty() || self.target_selector.len()>10 {return Err("Plan bounds exceeded".into())}
  let mut seen=std::collections::BTreeSet::new();
  let mut outputs=std::collections::BTreeSet::new();
  for n in &self.nodes {
   if !OPCODES.contains(&n.opcode.as_str()) || !seen.insert(n.id.clone()) {return Err("Unknown opcode or duplicate node".into())}
   if n.depends_on.iter().any(|d| d==&n.id || !seen.contains(d)) || n.inputs.iter().any(|s|!outputs.contains(s)){return Err("Invalid dependency order".into())}
   if let Some(o)=&n.output {if !outputs.insert(o.clone()){return Err("Duplicate dataset".into())}}
   if n.opcode=="simulate" && self.mode!="lab" {return Err("Simulation requires lab mode".into())}
   if !self.source_map.contains_key(&n.id){return Err("Missing source mapping".into())}
  }
  Ok(())
 }
}
#[cfg(test)] mod tests {use super::*; #[test] fn canonical_key_order(){assert_eq!(digest(&serde_json::json!({"b":1,"a":2})),digest(&serde_json::json!({"a":2,"b":1})));}}
