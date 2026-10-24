use crate::{Diagnostic,Token,err};
use jocky_ir::Span;
use serde_json::{Value,json};

pub fn parse(tokens:&[Token],span:&Span)->Result<Value,Diagnostic>{
    if tokens.len()>256 {return Err(err("E260","Predicate exceeds 256 tokens",span))}
    let mut parser=Parser{tokens,index:0,span};
    let value=parser.expression(0)?;
    if parser.index!=tokens.len(){return Err(err("E260","Unexpected predicate token",&tokens[parser.index].span))}
    Ok(value)
}
struct Parser<'a>{tokens:&'a[Token],index:usize,span:&'a Span}
impl Parser<'_>{
    fn consume(&mut self,text:&str)->bool{
        if self.tokens.get(self.index).is_some_and(|t|!t.quoted&&t.text==text){self.index+=1;true}else{false}
    }
    fn expression(&mut self,depth:usize)->Result<Value,Diagnostic>{
        let mut value=self.conjunction(depth)?;
        while self.consume("or"){value=json!({"op":"or","args":[value,self.conjunction(depth)?]});}
        Ok(value)
    }
    fn conjunction(&mut self,depth:usize)->Result<Value,Diagnostic>{
        let mut value=self.atom(depth)?;
        while self.consume("and"){value=json!({"op":"and","args":[value,self.atom(depth)?]});}
        Ok(value)
    }
    fn atom(&mut self,depth:usize)->Result<Value,Diagnostic>{
        if depth>16{return Err(err("E260","Predicate nesting exceeds 16",self.span))}
        if self.consume("not"){return Ok(json!({"op":"not","arg":self.atom(depth+1)?}))}
        if self.consume("("){
            let value=self.expression(depth+1)?;
            if !self.consume(")"){return Err(err("E260","Expected closing predicate parenthesis",self.span))}
            return Ok(value)
        }
        let remaining=&self.tokens[self.index..];
        if remaining.len()<3{return Err(err("E260","Expected field, comparison and literal",self.span))}
        let (field,op,value)=(&remaining[0],&remaining[1],&remaining[2]);
        if field.quoted||!field.text.split('.').all(|part|!part.is_empty()&&part.chars().all(|c|c.is_alphanumeric()||c=='_'))||op.quoted||!["==","!=","contains","startswith","endswith",">",">=","<","<="].contains(&op.text.as_str()){
            return Err(err("E260","Invalid field or comparison",&field.span))
        }
        let literal=if value.quoted{json!(value.text)}else{match value.text.as_str(){"true"=>json!(true),"false"=>json!(false),"null"=>Value::Null,_=>value.text.parse::<i64>().map(Value::from).unwrap_or_else(|_|json!(value.text))}};
        self.index+=3;
        Ok(json!({"field":field.text,"op":op.text,"value":literal}))
    }
}
