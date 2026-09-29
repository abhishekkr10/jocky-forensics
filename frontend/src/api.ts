let csrf='';
export function setCsrf(value:string){csrf=value}
export async function api<T=any>(path:string,body?:unknown):Promise<T>{
 const response=await fetch('/api/v1'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});
 const data=await response.json();
 if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));
 return data;
}
