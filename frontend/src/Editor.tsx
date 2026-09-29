import { useEffect, useRef } from 'react';
import { EditorView } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { basicSetup } from 'codemirror';
import { oneDark } from '@codemirror/theme-one-dark';
import { StreamLanguage } from '@codemirror/language';
import { setDiagnostics } from '@codemirror/lint';

const language = StreamLanguage.define({token(stream){
  if(stream.eatSpace())return null;
  if(stream.match('#')){stream.skipToEnd();return 'comment'}
  if(stream.match(/"(?:[^"\\]|\\.)*"/))return 'string';
  if(stream.match(/\b(mode|target|collect|import|simulate|filter|hunt|scan|correlate|timeline|risk|verify|report|export|compare|assert|as|on|using|within|where)\b/))return 'keyword';
  if(stream.match(/\b\d+[smhd]?\b/))return 'number';
  stream.next();return null;
}});
export type Diagnostic={code:string;message:string;span:{start:number;end:number;line:number;column:number}};
export default function Editor({value,onChange,diagnostics,focusLine}:{value:string;onChange:(s:string)=>void;diagnostics:Diagnostic[];focusLine:number}){
 const root=useRef<HTMLDivElement>(null),view=useRef<EditorView|null>(null),callback=useRef(onChange);callback.current=onChange;
 useEffect(()=>{if(!root.current)return;const v=new EditorView({state:EditorState.create({doc:value,extensions:[basicSetup,oneDark,language,EditorView.lineWrapping,EditorView.contentAttributes.of({'aria-label':'JOCKY source editor'}),EditorView.updateListener.of(u=>{if(u.docChanged)callback.current(u.state.doc.toString())})]}),parent:root.current});view.current=v;return()=>v.destroy()},[]);
 useEffect(()=>{const v=view.current;if(v&&v.state.doc.toString()!==value)v.dispatch({changes:{from:0,to:v.state.doc.length,insert:value}})},[value]);
 useEffect(()=>{const v=view.current;if(!v)return;v.dispatch(setDiagnostics(v.state,diagnostics.map(d=>{const line=v.state.doc.line(Math.min(d.span.line,v.state.doc.lines));return {from:line.from,to:line.to,severity:'error' as const,message:`${d.code}: ${d.message}`}})))},[diagnostics]);
 useEffect(()=>{const v=view.current;if(v&&focusLine){const line=v.state.doc.line(Math.min(focusLine,v.state.doc.lines));v.dispatch({selection:{anchor:line.from},effects:EditorView.scrollIntoView(line.from,{y:'center'})});v.focus()}},[focusLine]);
 return <div className="code-editor" ref={root}/>;
}
