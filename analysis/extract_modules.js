// 【安全声明】从解包后的小程序代码中按模块ID抽取函数体，仅用于安全研究与学习交流。
// 后果与作者本人无关。详见 安全声明.md。
const fs=require('fs'); const path=require('path');
const file=process.argv[2], out=process.argv[3]; const ids=process.argv.slice(4);
const s=fs.readFileSync(file,'utf8'); fs.mkdirSync(out,{recursive:true});
function findModule(id){
  const pats=[`"${id}":function`,`'${id}':function`,`${id}:function`];
  let pos=-1, pat='';
  for(const p of pats){ pos=s.indexOf(p); if(pos>=0){pat=p; break;} }
  if(pos<0) return null;
  const brace=s.indexOf('{', pos+pat.length-1); if(brace<0) return null;
  let i=brace, depth=0, str=null, esc=false, tmplDepth=0;
  for(; i<s.length; i++){
    const ch=s[i];
    if(str){
      if(esc){esc=false; continue;}
      if(ch==='\\'){esc=true; continue;}
      if(ch===str){str=null; continue;}
      continue;
    }
    if(ch==='"'||ch==="'"||ch==='`'){str=ch; continue;}
    if(ch==='{') depth++;
    else if(ch==='}') { depth--; if(depth===0){ return s.slice(pos, i+1); } }
  }
  return null;
}
for(const id of ids){ const m=findModule(id); if(!m){ console.log('[MISS]',id); continue;} const dst=path.join(out,`${id}.js`); fs.writeFileSync(dst,m); console.log('[OK]',id,m.length,dst); }
