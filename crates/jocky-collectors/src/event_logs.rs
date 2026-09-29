use serde_json::{json,Value};

pub fn parse_xml(xml:&str)->Result<Value,String>{
 use quick_xml::{Reader,events::Event};
 let mut reader=Reader::from_str(xml);reader.config_mut().trim_text(true);
 let mut record=serde_json::Map::new();let mut key=String::new();
 loop{match reader.read_event().map_err(|e|e.to_string())?{
  Event::Start(e)|Event::Empty(e)=>{
   let tag=String::from_utf8_lossy(e.name().as_ref()).into_owned();
   if tag=="EventID"{key="EventID".into()}
   for a in e.attributes(){let a=a.map_err(|e|e.to_string())?;let value=a.unescape_value().map_err(|e|e.to_string())?.into_owned();match (tag.as_str(),a.key.as_ref()){
    ("Data",b"Name")=>key=value,
    ("Provider",b"Name")=>{record.insert("Provider".into(),json!(value));},
    ("TimeCreated",b"SystemTime")=>{record.insert("event_time".into(),json!(value));},_=>{}
   }}
  },
  Event::Text(t)=>{if !key.is_empty(){record.insert(key.clone(),json!(t.unescape().map_err(|e|e.to_string())?.into_owned()));}},
  Event::End(_)=>key.clear(),Event::Eof=>break,_=>{}
 }}
 let id=record.get("EventID").and_then(Value::as_str).unwrap_or("");
 let provider=record.get("Provider").and_then(Value::as_str).unwrap_or("").to_owned();
 let process=(provider=="Microsoft-Windows-Sysmon"&&id=="1")||(provider=="Microsoft-Windows-Security-Auditing"&&id=="4688");
 let summary=format!("{provider} event {id}");
 if provider=="Microsoft-Windows-Security-Auditing"{if let Some(image)=record.get("NewProcessName").cloned(){record.insert("Image".into(),image);}}
 if let Some(guid)=record.get("ProcessGuid").cloned(){record.insert("process_key".into(),guid);}
 record.insert("event_kind".into(),json!(if process{"process_creation"}else{"windows_event"}));
 record.insert("product".into(),json!("windows"));record.insert("summary".into(),json!(summary));record.insert("raw_xml".into(),json!(xml));
 Ok(Value::Object(record))
}

#[cfg(windows)]
pub fn collect(max:usize,args:&Value)->Result<Value,String>{
 use std::{ffi::c_void,ptr,time::{Instant,Duration}};
 type Handle=*mut c_void;
 #[link(name="wevtapi")]
 extern "system"{
  fn EvtQuery(session:Handle,path:*const u16,query:*const u16,flags:u32)->Handle;
  fn EvtNext(result:Handle,size:u32,events:*mut Handle,timeout:u32,flags:u32,returned:*mut u32)->i32;
  fn EvtRender(context:Handle,event:Handle,flags:u32,size:u32,buffer:*mut c_void,used:*mut u32,properties:*mut u32)->i32;
  fn EvtClose(handle:Handle)->i32;
 }
 struct Owned(Handle);impl Drop for Owned{fn drop(&mut self){unsafe{EvtClose(self.0);}}}
 let millis=args["since"].as_str().and_then(|s|{let(n,u)=s.split_at(s.len().checked_sub(1)?);n.parse::<u64>().ok()?.checked_mul(match u{"s"=>1000,"m"=>60000,"h"=>3600000,"d"=>86400000,_=>return None})}).unwrap_or(86400000).min(604800000);
 let query:Vec<u16>=format!("*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]").encode_utf16().chain(Some(0)).collect();
 let mut rows=vec![];let mut warnings=vec![];let start=Instant::now();let mut bytes=0;
 for channel in ["Microsoft-Windows-Sysmon/Operational","Security","System"]{
  let path:Vec<u16>=channel.encode_utf16().chain(Some(0)).collect();
  let raw=unsafe{EvtQuery(ptr::null_mut(),path.as_ptr(),query.as_ptr(),1|512)};
  if raw.is_null(){warnings.push(format!("{channel}: {}",std::io::Error::last_os_error()));continue}
  let handle=Owned(raw);
  loop{
   if rows.len()>=max||start.elapsed()>Duration::from_secs(10)||bytes>=10485760{warnings.push("Historical log collection limit reached".into());break}
   let mut event=ptr::null_mut();let mut returned=0;
   if unsafe{EvtNext(handle.0,1,&mut event,1000,0,&mut returned)}==0{let e=std::io::Error::last_os_error();if e.raw_os_error()!=Some(259){warnings.push(format!("{channel}: {e}"))}break}
   if returned!=1||event.is_null(){break}let event=Owned(event);let mut used=0;let mut props=0;
   unsafe{EvtRender(ptr::null_mut(),event.0,1,0,ptr::null_mut(),&mut used,&mut props);}
   if used==0||used>1048576{warnings.push("Event XML exceeds bound".into());continue}
   let mut buf=vec![0u16;(used as usize+1)/2];let capacity=used;
   if unsafe{EvtRender(ptr::null_mut(),event.0,1,capacity,buf.as_mut_ptr().cast(),&mut used,&mut props)}==0{warnings.push(std::io::Error::last_os_error().to_string());continue}
   let xml=String::from_utf16_lossy(&buf[..buf.iter().position(|c|*c==0).unwrap_or(buf.len())]);bytes+=xml.len();
   match parse_xml(&xml){Ok(r)=>rows.push(r),Err(e)=>warnings.push(e)}
  }
  if rows.len()>=max{break}
 }
 Ok(json!({"rows":rows,"status":if warnings.is_empty(){"success"}else{"partial"},"warnings":warnings}))
}

#[cfg(not(windows))]
pub fn collect(max:usize,_args:&Value)->Result<Value,String>{
 use std::io::{BufRead,BufReader};
 let mut rows=vec![];let mut warnings=vec![];let mut bytes=0;
 for path in ["/var/log/auth.log","/var/log/syslog"]{
  match std::fs::File::open(path){Ok(file)=>{let mut reader=BufReader::new(file);let mut buf=Vec::new();loop{if rows.len()>=max||bytes>=1048576{warnings.push("Log byte/record limit reached".into());break}buf.clear();let n=reader.read_until(b'\n',&mut buf).map_err(|e|e.to_string())?;if n==0{break}bytes+=n;if n>65536{warnings.push("Oversized log line skipped".into());continue}rows.push(json!({"path":path,"event_kind":"linux_log","product":"linux","message":String::from_utf8_lossy(&buf),"summary":"Linux log record; original timestamp retained in message"}));}},Err(e)=>warnings.push(format!("{path}: {e}"))}
 }
 warnings.push("Coverage: bounded text log import; journal-only systems require an importer. Time-window filtering unavailable for unparsed text timestamps.".into());
 Ok(json!({"rows":rows,"status":"partial","warnings":warnings}))
}

#[cfg(test)]mod tests{use super::*;
 #[test]fn maps_sysmon_without_inventing_fields(){let v=parse_xml(r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-09-30T00:00:00Z"/></System><EventData><Data Name="Image">C:\Windows\powershell.exe</Data><Data Name="ProcessGuid">guid</Data></EventData></Event>"#).unwrap();assert_eq!(v["event_kind"],"process_creation");assert_eq!(v["process_key"],"guid");assert!(v.get("CommandLine").is_none());}
}
