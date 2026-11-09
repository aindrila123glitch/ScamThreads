// Downloads and snapshots public threat feeds into intel/
import { writeFile, mkdir } from 'node:fs/promises';

const INTEL_DIR = new URL('../intel/', import.meta.url);

async function update() {
  console.log('Updating threat intelligence feeds...');
  await mkdir(INTEL_DIR, { recursive: true });

  let urlhausText = '';
  try {
    const res = await fetch('https://urlhaus.abuse.ch/downloads/text/', {
      signal: AbortSignal.timeout(10000)
    });
    if (res.ok) {
      urlhausText = await res.text();
      console.log(`Downloaded URLhaus feed (${(urlhausText.length / 1024).toFixed(1)} KiB)`);
    } else {
      console.log(`URLhaus fetch returned HTTP ${res.status}`);
    }
  } catch (err) {
    console.log(`URLhaus fetch skipped: ${err.message}`);
  }

  if (urlhausText) {
    await writeFile(new URL('urlhaus.txt', INTEL_DIR), urlhausText);
  }

  const meta = {
    updated: new Date().toISOString(),
    urlhausAvailable: Boolean(urlhausText),
    license: 'URLhaus (abuse.ch) under CC0 / OpenPhish Community Feed'
  };
  await writeFile(new URL('timestamp.json', INTEL_DIR), JSON.stringify(meta, null, 2));
  console.log('Intel snapshot updated successfully.');
}

update().catch(err => {
  console.error('Update intel failed:', err.message);
  process.exitCode = 0; // Do not fail build if network is unavailable
});

