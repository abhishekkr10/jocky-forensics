use serde_json::{Value,json};
use std::{ffi::c_void,ptr};
type Handle=*mut c_void;
#[link(name="advapi32")]
extern "system" {
 fn RegOpenKeyExW(root:Handle,path:*const u16,options:u32,access:u32,result:*mut Handle)->i32;
 fn RegEnumValueW(key:Handle,index:u32,name:*mut u16,name_len:*mut u32,reserved:*mut u32,kind:*mut u32,data:*mut u8,data_len:*mut u32)->i32;
 fn RegCloseKey(key:Handle)->i32;
 fn OpenSCManagerW(machine:*const u16,database:*const u16,access:u32)->Handle;
 fn EnumServicesStatusExW(manager:Handle,level:u32,kind:u32,state:u32,buffer:*mut u8,size:u32,needed:*mut u32,count:*mut u32,resume:*mut u32,group:*const u16)->i32;
 fn CloseServiceHandle(handle:Handle)->i32;
}
fn wide(value:&str)->Vec<u16>{value.encode_utf16().chain(Some(0)).collect()}
pub fn registry(max:usize)->Result<Value,String>{
 let mut rows=vec![];let mut warnings:Vec<String>=vec![];
 for (label,root) in [("HKCU",(-2147483647isize) as Handle),("HKLM",(-2147483646isize) as Handle)]{
  for path in ["Software\\Microsoft\\Windows\\CurrentVersion\\Run","Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"]{
   let mut key=ptr::null_mut();let status=unsafe{RegOpenKeyExW(root,wide(path).as_ptr(),0,0x20019,&mut key)};
   if status!=0{warnings.push(format!("{label}\\{path}: registry error {status}"));continue}
   let mut index=0;
   loop{
    if rows.len()>=max{warnings.push("Registry record limit reached".into());break}
    let mut name=vec![0u16;16384];let mut data=vec![0u8;65536];let(mut name_len,mut data_len,mut kind)=(name.len() as u32,data.len() as u32,0);
    let status=unsafe{RegEnumValueW(key,index,name.as_mut_ptr(),&mut name_len,ptr::null_mut(),&mut kind,data.as_mut_ptr(),&mut data_len)};index+=1;
    if status==259{break}
    if status!=0{warnings.push(format!("Registry enumeration error {status}"));if status!=234{break}continue}
    if ![1,2].contains(&kind){continue}
    let chars:Vec<u16>=data[..data_len as usize].chunks_exact(2).map(|v|u16::from_le_bytes([v[0],v[1]])).take_while(|v|*v!=0).collect();
    rows.push(json!({"registry_key":format!("{label}\\{path}"),"name":String::from_utf16_lossy(&name[..name_len as usize]),"command":String::from_utf16_lossy(&chars),"registry_type":kind,"summary":"Observed registry startup value"}));
   }
   unsafe{RegCloseKey(key);}
  }
 }
 warnings.push("Coverage: current-user and machine Run/RunOnce keys in the worker's registry view; values are never executed".into());
 Ok(json!({"rows":rows,"status":"partial","warnings":warnings}))
}
#[repr(C)]
struct ServiceStatus{kind:u32,state:u32,controls:u32,win32_exit:u32,service_exit:u32,checkpoint:u32,wait_hint:u32,pid:u32,flags:u32}
#[repr(C)]
struct Service{ name:*const u16,display:*const u16,status:ServiceStatus }
pub fn services(max:usize)->Result<Value,String>{
 let manager=unsafe{OpenSCManagerW(ptr::null(),ptr::null(),4)};
 if manager.is_null(){return Err(std::io::Error::last_os_error().to_string())}
 // A u64 allocation supplies alignment for OS structures and UTF-16 strings.
 let mut buffer=vec![0u64;32768];let(mut needed,mut count,mut resume)=(0,0,0);
 let success=unsafe{EnumServicesStatusExW(manager,0,0x30,3,buffer.as_mut_ptr().cast(),262144,&mut needed,&mut count,&mut resume,ptr::null())};
 let error=std::io::Error::last_os_error();unsafe{CloseServiceHandle(manager);}
 if success==0&&error.raw_os_error()!=Some(234){return Err(error.to_string())}
 let mut rows=vec![];let mut warnings:Vec<String>=vec![];
 let base=buffer.as_ptr() as usize;let end=base+262144;
 let text=|pointer:*const u16|{let start=pointer as usize;if start<base||start>=end||start%2!=0{return String::new()}let limit=((end-start)/2).min(512);let chars=unsafe{std::slice::from_raw_parts(pointer,limit)};String::from_utf16_lossy(&chars[..chars.iter().position(|c|*c==0).unwrap_or(limit)])};
 let bound=(262144/std::mem::size_of::<Service>()).min(count as usize).min(max);
 for i in 0..bound{let service=unsafe{&*buffer.as_ptr().cast::<Service>().add(i)};rows.push(json!({"name":text(service.name),"display_name":text(service.display),"state":service.status.state,"pid":service.status.pid,"summary":format!("Windows service {}",text(service.name))}));}
 if success==0||count as usize>max{warnings.push("Service enumeration truncated by buffer or record limit".into())}
 warnings.push("Coverage: Win32 services and observed state only; service configuration and drivers are not enumerated".into());
 Ok(json!({"rows":rows,"status":"partial","warnings":warnings}))
}
