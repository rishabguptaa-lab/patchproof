import { promises as fs } from 'node:fs';
import path from 'node:path';

export async function loadPolicy(root){
  const defaults={failOn:'high',exclude:['node_modules/**','dist/**','build/**','coverage/**'],rules:{}};
  for(const name of ['.patchproof.yml','.patchproof.yaml']){ try{const text=await fs.readFile(path.join(root,name),'utf8'); const parsed=parseSimpleYaml(text); return policy({...defaults,...parsed,rules:{...defaults.rules,...parsed.rules}});}catch(error){if(error.code!=='ENOENT') throw error;} }
  return policy(defaults);
}
function policy(config){return{...config,ruleEnabled(id){return config.rules?.[id]!=='off'&&config.rules?.[id]!==false;},isExcluded(file){return (config.exclude||[]).some(pattern=>glob(file,pattern));}};}
function glob(file,pattern){const escaped=pattern.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*\*/g,'.*').replace(/\*/g,'[^/]*');return new RegExp(`^${escaped}$`).test(file);}
function parseSimpleYaml(text){const out={rules:{},exclude:[]}; let section=''; for(const raw of text.split(/\r?\n/)){const line=raw.replace(/#.*$/,'').trimEnd();if(!line.trim())continue;if(!line.startsWith(' ')){const [key,...rest]=line.split(':');section=key.trim();const value=rest.join(':').trim();if(value)out[toCamel(section)]=scalar(value);continue;}const trimmed=line.trim();if(section==='exclude'&&trimmed.startsWith('- '))out.exclude.push(trimmed.slice(2).trim());else if(section==='rules'){const [k,...v]=trimmed.split(':');out.rules[k.trim()]=scalar(v.join(':').trim());}}return out;}
function scalar(v){if(v==='true')return true;if(v==='false')return false;return v.replace(/^['"]|['"]$/g,'');} function toCamel(v){return v.replace(/-([a-z])/g,(_,c)=>c.toUpperCase());}
