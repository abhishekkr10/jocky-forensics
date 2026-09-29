use serde_json::{Value,json};
use std::collections::{BTreeMap,BTreeSet};
pub fn analyze(evidence:&[Value],detections:&[Value])->Value{
 let mut timeline=vec![];let mut edges=vec![];let mut entities:BTreeMap<String,Vec<String>>=BTreeMap::new();
 for e in evidence {let id=e["evidence_id"].as_str().unwrap_or("");let event=e["event_time"].as_str();timeline.push(json!({"event_time":e["event_time"],"observed_at":e["observed_at"],"sort_time":event.unwrap_or(e["observed_at"].as_str().unwrap_or("")),"time_kind":if event.is_some(){"event"}else{"observation"},"uncertainty":e["time_metadata"]["uncertainty"],"endpoint_id":e["endpoint_id"],"evidence_ids":[id],"detection_ids":detections.iter().filter(|d|d["evidence_ids"].as_array().map(|xs|xs.contains(&json!(id))).unwrap_or(false)).map(|d|d["id"].clone()).collect::<Vec<_>>(),"summary":e["payload"]["summary"].as_str().unwrap_or(e["event_kind"].as_str().unwrap_or("Observation")),"provenance_kind":e["provenance_kind"]}));
  if let Some(key)=e["entities"]["process_key"].as_str(){let scope=format!("{}:{}:{}",e["endpoint_id"],e["provenance_kind"],key);let xs=entities.entry(scope).or_default();if let Some(first)=xs.first(){edges.push(json!({"source":first,"target":id,"reason":"Same endpoint and stable process identity","profile":"triage-v1","confidence":"high","evidence_ids":[first,id]}))}xs.push(id.into());}
 }
 for d in detections{if let Some(ids)=d["evidence_ids"].as_array(){for id in ids {edges.push(json!({"source":id,"target":d["id"],"reason":"Rule evaluated this evidence","profile":"triage-v1","confidence":"high","evidence_ids":[id]}));}}}
 timeline.sort_by(|a,b|a["sort_time"].as_str().cmp(&b["sort_time"].as_str()));
 let mut families=BTreeSet::new();let mut contributions=vec![];for d in detections{let family=d["engine"].as_str().unwrap_or("unknown");if families.insert(family){contributions.push(json!({"reason":format!("{family} detection family"),"points":25,"detection_id":d["id"]}));}}
 let score=contributions.len()*25;let lab=evidence.iter().any(|e|e["provenance_kind"]=="synthetic");
 json!({"timeline":timeline,"edges":edges,"risk":{"score":score.min(100),"label":if lab{"LAB RISK SCORE"}else{"TRIAGE SCORE"},"contributions":contributions,"disclaimer":"Triage heuristic, not probability of compromise. Missing telemetry is not evidence of low risk."}})
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn no_temporal_causality(){let es=vec![json!({"evidence_id":"1","observed_at":"2026-01-01","entities":{}}),json!({"evidence_id":"2","observed_at":"2026-01-01","entities":{}})];let r=analyze(&es,&[]);assert_eq!(r["edges"].as_array().unwrap().len(),0);assert_eq!(r["timeline"][0]["time_kind"],"observation");}
}
