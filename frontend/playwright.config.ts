import { defineConfig } from '@playwright/test';
import path from 'node:path';
const root=path.resolve('..');
const e2eData=path.join(root,'artifacts','e2e-data');
const python=process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python';
const apiCommand=`"${path.join(root,python)}" -c "import os,shutil; shutil.rmtree(r'${e2eData}',ignore_errors=True); os.makedirs(r'${e2eData}',exist_ok=True); os.environ['JOCKY_DATA']=r'${e2eData}'; import uvicorn; uvicorn.run('backend.app.main:app',host='127.0.0.1',port=8011)"`;
export default defineConfig({testDir:'tests/e2e',timeout:60000,workers:1,use:{baseURL:'http://127.0.0.1:8011',viewport:{width:1440,height:1000},trace:'retain-on-failure'},webServer:{command:apiCommand,cwd:root,url:'http://127.0.0.1:8011/api/v1/health',reuseExistingServer:false,env:{...process.env,JOCKY_DATA:e2eData,JOCKY_KEY_PATH:path.join(e2eData,'keys','checkpoint.key')},timeout:30000}});
