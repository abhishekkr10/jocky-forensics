import { afterEach,expect,test,vi } from 'vitest';
import { api,setCsrf } from './api';
afterEach(()=>vi.unstubAllGlobals());
test('mutating requests carry session-bound CSRF and use same-origin credentials',async()=>{
 const fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({ok:true})});vi.stubGlobal('fetch',fetch);setCsrf('test-csrf');await api('/investigations',{name:'test'});
 expect(fetch).toHaveBeenCalledWith('/api/v1/investigations',expect.objectContaining({method:'POST',credentials:'same-origin',headers:expect.objectContaining({'X-CSRF-Token':'test-csrf'})}));
});
test('API errors surface actionable server diagnostics',async()=>{
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,json:async()=>({detail:'Invalid credentials'})}));await expect(api('/auth/login',{})).rejects.toThrow('Invalid credentials');
});
