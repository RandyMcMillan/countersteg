/* countersteg web glue: loads the zero-import wasm module and wraps the
 * raw FFI (alloc/dealloc + ptr/len pairs) in friendly async functions.
 * Loads countersteg_wasm.wasm (CI deploys) or countersteg_wasm.b64
 * (branch deploys, where binary uploads are not scope-friendly). */

const enc = new TextEncoder();
const dec = new TextDecoder();

let ex = null;

async function loadWasm() {
  if (ex) return;
  try {
    const resp = await fetch('countersteg_wasm.wasm');
    if (resp.ok) {
      const { instance } = await WebAssembly.instantiateStreaming(resp, {});
      ex = instance.exports;
      return;
    }
  } catch (_) { /* fall through to base64 variant */ }
  const resp = await fetch('countersteg_wasm.b64');
  if (!resp.ok) throw new Error('wasm not found (expected .wasm or .b64 next to app.js)');
  const bin = atob((await resp.text()).trim());
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const { instance } = await WebAssembly.instantiate(bytes, {});
  ex = instance.exports;
}

function writeBytes(bytes) {
  const ptr = ex.alloc(bytes.length || 1);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

const writeString = (s) => writeBytes(enc.encode(s));

function readOutput() {
  const ptr = ex.output_ptr();
  const len = ex.output_len();
  return new Uint8Array(ex.memory.buffer, ptr, len).slice();
}

function readError() {
  return dec.decode(readOutput());
}

async function composeMidi(seed, bars) {
  await loadWasm();
  if (ex.compose_midi(BigInt(seed), bars | 0) !== 0) throw new Error(readError());
  return readOutput();
}

async function embedMidi(message, passphrase, seed, minLen) {
  await loadWasm();
  const [mp, ml] = writeString(message);
  const [pp, pl] = writeString(passphrase);
  if (ex.embed_midi(mp, ml, pp, pl, BigInt(seed), minLen | 0) !== 0) {
    throw new Error(readError());
  }
  return readOutput();
}

async function extractMessage(midiBytes, passphrase) {
  await loadWasm();
  const [ip, il] = writeBytes(midiBytes);
  const [pp, pl] = writeString(passphrase);
  if (ex.extract_message(ip, il, pp, pl) !== 0) throw new Error(readError());
  return dec.decode(readOutput());
}

function download(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'audio/midi' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.textContent = `download ${name}`;
  return a;
}

function show(id, kind, node) {
  const el = document.getElementById(id);
  el.className = `out ${kind}`;
  el.textContent = '';
  if (node !== undefined) {
    if (typeof node === 'string') el.textContent = node;
    else el.appendChild(node);
  }
  return el;
}

/* ---- UI wiring ---- */

document.querySelectorAll('.tabs button').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('active', x === b));
    document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `tab-${b.dataset.tab}`));
  });
});

const seedName = (seed) => String(seed).replace(/[^0-9]/g, '') || '0';

document.getElementById('btn-compose').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  try {
    const seed = document.getElementById('c-seed').value;
    const midi = await composeMidi(seed, document.getElementById('c-bars').value);
    const el = show('out-compose', 'ok', download(midi, `countersteg-compose-${seedName(seed)}.mid`));
    el.append(`\n${midi.length} bytes SMF (seed:${seed})`);
  } catch (e) {
    show('out-compose', 'bad', e.message);
  } finally {
    ev.target.disabled = false;
  }
});

document.getElementById('btn-embed').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  try {
    const seed = document.getElementById('e-seed').value;
    const msg = document.getElementById('e-msg').value;
    const midi = await embedMidi(
      msg,
      document.getElementById('e-pass').value,
      seed,
      document.getElementById('e-bars').value,
    );
    const el = show('out-embed', 'ok', download(midi, `countersteg-embed-${seedName(seed)}.mid`));
    el.append(`\n${msg.length} bytes hidden in ${midi.length} bytes of counterpoint (seed:${seed})`);
  } catch (e) {
    show('out-embed', 'bad', e.message);
  } finally {
    ev.target.disabled = false;
  }
});

document.getElementById('btn-extract').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  try {
    const file = document.getElementById('x-file').files[0];
    if (!file) throw new Error('choose a .mid file first');
    const msg = await extractMessage(new Uint8Array(await file.arrayBuffer()), document.getElementById('x-pass').value);
    show('out-extract', 'ok', `message (${msg.length} bytes):\n${msg}`);
  } catch (e) {
    show('out-extract', 'bad', e.message);
  } finally {
    ev.target.disabled = false;
  }
});
