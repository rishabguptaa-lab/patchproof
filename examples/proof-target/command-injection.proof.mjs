import { showRevision } from './command.js';
const output=await showRevision('main; printf PATCHPROOF_EXECUTION_PROOF');
if(!output.includes('PATCHPROOF_EXECUTION_PROOF')){console.error('Injection was not reproduced');process.exit(1);}
console.log('PATCHPROOF_EXECUTION_PROOF');
