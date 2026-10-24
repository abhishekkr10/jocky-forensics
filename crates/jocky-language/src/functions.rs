use crate::{Ast,Diagnostic,Cursor,err};
use std::collections::BTreeMap;

pub fn expand(ast:Ast)->Result<Ast,Diagnostic>{
 let mut functions=BTreeMap::new();let mut main=vec![];let mut iter=ast.statements.into_iter();
 while let Some(statement)=iter.next(){
  if statement.keyword!="function"{main.push(statement);continue}
  let mut cursor=Cursor{ts:&statement.tokens,i:0,span:&statement.span};
  let name=cursor.binding()?;cursor.word("(")?;let parameter=cursor.binding()?;cursor.word(")")?;cursor.done()?;
  let mut body=vec![];let mut returned=None;let mut closed=false;
  for item in iter.by_ref(){
   if item.keyword=="end"{if !item.tokens.is_empty(){return Err(err("E270","Unexpected tokens after end",&item.span))}closed=true;break}
   if returned.is_some(){return Err(err("E270","return must be the last function statement",&item.span))}
   if item.keyword=="return"{let mut c=Cursor{ts:&item.tokens,i:0,span:&item.span};returned=Some(c.binding()?);c.done()?;continue}
   if !["collect","simulate","import","filter","assert","hunt","scan","correlate","timeline","risk","compare"].contains(&item.keyword.as_str()){return Err(err("E270","Functions accept bounded dataset operations only; nesting and recursion are unsupported",&item.span))}
   body.push(item);
  }
  if !closed||returned.is_none()||body.is_empty(){return Err(err("E270","Function requires a body, return dataset and end",&statement.span))}
  if functions.insert(name,(parameter,body,returned.unwrap())).is_some(){return Err(err("E270","Duplicate function definition",&statement.span))}
 }
 let mut expanded=vec![];let mut call=0;
 for statement in main{
  if statement.keyword!="call"{expanded.push(statement);continue}
  call+=1;
  let mut cursor=Cursor{ts:&statement.tokens,i:0,span:&statement.span};
  let name=cursor.binding()?;cursor.word("(")?;let argument=cursor.binding()?;cursor.word(")")?;cursor.word("as")?;let output=cursor.binding()?;cursor.done()?;
  let (parameter,body,returned)=functions.get(&name).ok_or_else(||err("E270","Undefined function",&statement.span))?;
  let mut bindings=BTreeMap::from([(parameter.clone(),argument)]);
  for original in body{
   let mut item=original.clone();item.span=statement.span.clone();
   let mut inputs=vec![];
   match item.keyword.as_str(){
    "filter"|"assert"|"timeline"|"risk"=>inputs.push(0),
    "compare"=>inputs.extend([0,2]),
    "hunt"|"scan"=>{if item.tokens.len()>3{inputs.push(3)}},
    "correlate"=>{for (i,t) in item.tokens.iter().enumerate().skip(1){if t.text=="]"{break}if t.text!=","{inputs.push(i)}}},_=>{}
   }
   for index in inputs{let token=item.tokens.get_mut(index).ok_or_else(||err("E270","Incomplete function operation",&statement.span))?;token.text=bindings.get(&token.text).ok_or_else(||err("E270","Function references an undefined dataset",&statement.span))?.clone();}
   if item.keyword!="assert"{
    let index=item.tokens.len().checked_sub(1).ok_or_else(||err("E270","Function operation requires output",&statement.span))?;
    if index==0||item.tokens[index-1].text!="as"{return Err(err("E270","Function operation requires as binding",&statement.span))}
    let local=item.tokens[index].text.clone();
    if bindings.contains_key(&local){return Err(err("E270","Function datasets are immutable",&statement.span))}
    let mapped=if &local==returned{output.clone()}else{format!("__call{call}_{local}")};bindings.insert(local,mapped.clone());item.tokens[index].text=mapped;
   }
   expanded.push(item);
   if expanded.len()>512{return Err(err("E270","Function expansion exceeds 512 statements",&statement.span))}
  }
  if !bindings.contains_key(returned)||returned==parameter{return Err(err("E270","Function must return a locally produced dataset",&statement.span))}
 }
 Ok(Ast{statements:expanded})
}
