import {build} from 'esbuild';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shipped = path.join(root, 'web/assets');
const checking = process.argv.includes('--check');
// Build in isolation so removed fonts and failed builds cannot leave stale assets.
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'qshield-web-'));
const output = temporary;

async function manifest(directory, prefix='') {
  const files = {};
  for (const entry of (await fs.readdir(directory, {withFileTypes:true})).sort((a,b)=>a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const relative = prefix + entry.name;
    if (entry.isDirectory()) Object.assign(files, await manifest(path.join(directory, entry.name), relative+'/'));
    else if (relative !== 'manifest.json') files[relative] = crypto.createHash('sha256').update(await fs.readFile(path.join(directory, entry.name))).digest('hex');
  }
  return files;
}

try {
  await fs.mkdir(output, {recursive:true});
  await build({
    absWorkingDir:root, entryPoints:['web/src/app.jsx'], outfile:path.join(output,'app.js'),
    bundle:true, minify:true, format:'iife', target:['es2020'],
    define:{'process.env.NODE_ENV':'"production"'}, legalComments:'eof',
    loader:{'.woff2':'file','.woff':'file'}, assetNames:'fonts/[name]-[hash]',
  });
  await promisify(execFile)(process.execPath, [path.join(root,'node_modules/tailwindcss/lib/cli.js'),
    '-c', path.join(root,'tailwind.config.cjs'), '-i', path.join(root,'web/src/tailwind.css'),
    '-o', path.join(output,'utilities.css'), '--minify'], {cwd:root});
  await fs.mkdir(path.join(output,'licenses'),{recursive:true});
  for (const [name, source] of Object.entries({
    'React.txt':'react/LICENSE',
    'React-DOM.txt':'react-dom/LICENSE',
    'Manrope.txt':'@fontsource/manrope/LICENSE',
    'Barlow-Condensed.txt':'@fontsource/barlow-condensed/LICENSE',
    'IBM-Plex-Mono.txt':'@fontsource/ibm-plex-mono/LICENSE',
  })) await fs.copyFile(path.join(root,'node_modules',source),path.join(output,'licenses',name));
  const pkg = JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8'));
  const data = {version:pkg.version, files:await manifest(output)};
  if (checking) {
    const existing = JSON.parse(await fs.readFile(path.join(shipped,'manifest.json'),'utf8'));
    if (JSON.stringify(data)!==JSON.stringify(existing)) throw Error('Dashboard assets are stale. Run npm run build:web.');
    const actual = await manifest(shipped);
    if (JSON.stringify(actual)!==JSON.stringify(data.files)) throw Error('Shipped asset bytes differ from the manifest.');
    console.log('Dashboard assets match the pinned source build.');
  } else {
    await fs.writeFile(path.join(output,'manifest.json'),JSON.stringify(data,null,2)+'\n');
    await fs.rm(shipped,{recursive:true,force:true});
    await fs.cp(output,shipped,{recursive:true});
    console.log('Built local dashboard assets ('+Object.keys(data.files).length+' files).');
  }
} finally {
  if (temporary) await fs.rm(temporary,{recursive:true,force:true});
}
