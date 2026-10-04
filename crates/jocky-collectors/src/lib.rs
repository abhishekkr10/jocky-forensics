use serde_json::{Value,json};
use std::{fs,path::Path};
use sysinfo::{Pid,System};
mod event_logs;
mod files;
pub fn manifests()->Value{json!(["system_information","processes","network_connections","startup_items","files","event_logs"].iter().map(|id|json!({"id":id,"version":"0.1.0","supported_os":["windows","linux"],"argument_schema":{"max_records":"integer 1..10000","root":"approved directory for files"},"output_schema":id,"required_permissions":"current user; permission failures reported","provided_fields":match *id{"processes"=>vec!["pid","ppid","name","executable","start_time"],"network_connections"=>vec!["source","destination","protocol","port"],_=>vec![]},"event_categories":if *id=="processes"{"process_snapshot"}else{*id},"resource_limits":{"records":10000,"bytes":10485760,"seconds":30}})).collect::<Vec<_>>())}
pub fn collect(name:&str,args:&Value,approved_root:&Path)->Result<Value,String>{
 let max=args["max_records"].as_u64().unwrap_or(1000).min(10000) as usize;let mut rows=vec![];let mut warnings=vec![];
 match name {
 "system_information"=>rows.push(json!({"hostname":System::host_name(),"os":System::name(),"os_version":System::os_version(),"architecture":std::env::consts::ARCH,"boot_time":System::boot_time(),"summary":"System information snapshot"})),
 "processes"=>{let s=System::new_all();for (pid,p) in s.processes(){if rows.len()>=max{warnings.push("Record limit reached".to_string());break}rows.push(json!({"pid":pid.as_u32(),"ppid":p.parent().map(|v|v.as_u32()),"name":p.name().to_string_lossy(),"executable":p.exe().map(|v|v.to_string_lossy()),"start_time":p.start_time(),"process_key":format!("{}:{}:{}",System::boot_time(),pid,p.start_time()),"summary":p.name().to_string_lossy()}));}},
 "network_connections"=>{use netstat2::*;let sockets=get_sockets_info(AddressFamilyFlags::IPV4|AddressFamilyFlags::IPV6,ProtocolFlags::TCP|ProtocolFlags::UDP).map_err(|e|e.to_string())?;let processes=System::new_all();let boot=System::boot_time();for s in sockets.into_iter().take(max){let process_key=if s.associated_pids.len()==1{s.associated_pids.first().and_then(|pid|processes.process(Pid::from_u32(*pid)).map(|p|format!("{}:{}:{}",boot,pid,p.start_time())))}else{None};match s.protocol_socket_info {ProtocolSocketInfo::Tcp(t)=>rows.push(json!({"source":t.local_addr.to_string(),"source_port":t.local_port,"destination":t.remote_addr.to_string(),"port":t.remote_port,"protocol":"tcp","pids":s.associated_pids,"process_key":process_key,"summary":format!("TCP {}:{}",t.remote_addr,t.remote_port)})),ProtocolSocketInfo::Udp(u)=>rows.push(json!({"source":u.local_addr.to_string(),"source_port":u.local_port,"protocol":"udp","pids":s.associated_pids,"process_key":process_key,"summary":"UDP socket"}))}}},
 "files"=>{let (file_rows,file_warnings)=files::collect(args,approved_root)?;rows=file_rows;warnings.extend(file_warnings)},
 "startup_items"=>{let roots:Vec<std::path::PathBuf>=if cfg!(windows){std::env::var_os("APPDATA").map(|v|vec![std::path::PathBuf::from(v).join("Microsoft/Windows/Start Menu/Programs/Startup")]).unwrap_or_default()}else{vec!["/etc/systemd/system".into(),"/etc/xdg/autostart".into()]};for root in roots{match fs::read_dir(root){Ok(xs)=>for e in xs.take(max).flatten(){rows.push(json!({"path":e.path().to_string_lossy(),"summary":e.file_name().to_string_lossy()}))},Err(e)=>warnings.push(e.to_string())}}warnings.push("Coverage: selected startup directories only; registry and other persistence artifacts not collected".into());},
 "event_logs"=>return event_logs::collect(max,args),
 _=>return Err("Unknown collector".into())
 }
 Ok(json!({"rows":rows,"status":if warnings.is_empty(){"success"}else{"partial"},"warnings":warnings}))
}
#[cfg(test)]mod tests{use super::*;#[test]fn real_system(){assert_eq!(collect("system_information",&json!({}),Path::new(".")).unwrap()["rows"].as_array().unwrap().len(),1)}#[test]fn bounds(){assert!(collect("files",&json!({"root":".."}),Path::new(".")).is_err())}}
