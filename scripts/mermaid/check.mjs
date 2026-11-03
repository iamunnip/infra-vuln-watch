// Read a JSON list of Mermaid diagrams from stdin and print a list of parse errors, null for none.
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><body></body>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false });

const results = [];
for (const diagram of JSON.parse(readFileSync(0, 'utf8'))) {
  try {
    await mermaid.parse(diagram);
    results.push(null);
  } catch (error) {
    results.push(String(error.message));
  }
}
console.log(JSON.stringify(results));
