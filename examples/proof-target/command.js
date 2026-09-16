import { exec } from 'node:child_process';
export function showRevision(ref){return new Promise((resolve,reject)=>exec(`printf revision:${ref}`,(error,stdout)=>error?reject(error):resolve(stdout)));}
