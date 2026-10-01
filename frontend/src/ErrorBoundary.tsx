import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ShieldAlert } from 'lucide-react';

export default class ErrorBoundary extends Component<{children:ReactNode},{failed:boolean}> {
 state={failed:false};
 static getDerivedStateFromError(){return {failed:true}}
 componentDidCatch(error:Error, info:ErrorInfo){console.error('Investigation view failed',error,info.componentStack)}
 render(){return this.state.failed?<div className="view-error" role="alert"><ShieldAlert size={28}/><h1>This view could not be displayed</h1><p>Your investigation remains saved. Reload the console to try again.</p><button className="secondary" onClick={()=>window.location.reload()}>Reload console</button></div>:this.props.children}
}
