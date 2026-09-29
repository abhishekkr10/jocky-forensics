import { defineConfig } from '@playwright/test';
import path from 'node:path';
const root=path.resolve('..');
const python=process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python';
export default defineConfig({testDir:'tests/e2e',timeout:60000,workers:1,use:{baseURL:'http://127.0.0.1:8011',viewport:{width:1440,height:1000},trace:'retain-on-failure'},webServer:{command:`"${path.join(root,python)}" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8011`,cwd:root,url:'http://127.0.0.1:8011/api/v1/health',reuseExistingServer:false,env:{JOCKY_DATA:path.join(root,'artifacts','e2e-data')},timeout:30000}});
