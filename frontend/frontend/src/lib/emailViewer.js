function decodeQuotedPrintable(value) {
  const normalized = String(value ?? '').replace(/=\r?\n/g, '');
  try {
    const bytes = normalized.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return decodeURIComponent(escape(bytes));
  } catch {
    return normalized.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
}

function decodeMimeBody(value, encoding = '') {
  const v = String(value ?? '');
  const e = String(encoding ?? '').toLowerCase();
  if (e.includes('quoted-printable')) return decodeQuotedPrintable(v);
  if (e.includes('base64')) {
    try {
      const bytes = atob(v.replace(/\s+/g, ''));
      let out = '';
      for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes.charCodeAt(i));
      try { return decodeURIComponent(escape(out)); } catch { return out; }
    } catch { return v; }
  }
  return v;
}

function unfoldHeaders(text) {
  const lines = String(text ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const out = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += ` ${line.trim()}`;
    else out.push(line);
  }
  return out;
}

function parseHeaderBlock(text) {
  const out = {};
  for (const line of unfoldHeaders(text)) {
    const match = line.match(/^([^:]+):\s*(.*)$/);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    if (!(key in out)) out[key] = match[2].trim();
  }
  return out;
}

function splitHeadersBody(text) {
  const normalized = String(text ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const idx = normalized.indexOf('\n\n');
  if (idx < 0) return { headers: normalized, body: '' };
  return { headers: normalized.slice(0, idx), body: normalized.slice(idx + 2) };
}

function unquoteMimeParameter(value) {
  return String(value ?? '').replace(/^"|"$/g, '').replace(/\\(.)/g, '$1');
}

function getMimeParameter(headerValue, key) {
  const source = String(headerValue ?? '');
  const rx = new RegExp(`${key}\\s*=\\s*(?:"([^"]+)"|([^;\\s]+))`, 'i');
  const match = source.match(rx);
  return match ? unquoteMimeParameter(match[1] ?? match[2]) : null;
}

function stripHtmlToText(html) {
  try {
    const doc = new DOMParser().parseFromString(String(html ?? ''), 'text/html');
    doc.querySelectorAll('script,style,noscript,template').forEach((node) => node.remove());
    const links = Array.from(doc.querySelectorAll('a[href]'));
    for (const link of links) {
      const href = link.getAttribute('href');
      const label = (link.textContent || '').trim();
      if (href && label && label !== href) link.appendChild(doc.createTextNode(` (${href})`));
    }
    return (doc.body?.innerText || doc.body?.textContent || '').replace(/\u00a0/g, ' ');
  } catch {
    return String(html ?? '').replace(/<[^>]+>/g, ' ');
  }
}

function walkMime(text, inheritedHeaders = {}) {
  const { headers: rawHeaders, body } = splitHeadersBody(text);
  const headers = { ...inheritedHeaders, ...parseHeaderBlock(rawHeaders) };
  const contentType = headers['content-type'] || 'text/plain; charset=utf-8';
  const encoding = headers['content-transfer-encoding'] || '';
  const boundary = getMimeParameter(contentType, 'boundary');

  if (/multipart\//i.test(contentType) && boundary) {
    const marker = `--${boundary}`;
    const pieces = body.split(marker);
    const children = [];
    for (const piece of pieces.slice(1)) {
      if (/^--/.test(piece.trim())) break;
      const child = piece.replace(/^\s*\r?\n/, '').replace(/\r?\n\s*$/, '');
      if (child) children.push(walkMime(child, headers));
    }
    const html = children.find((item) => item.kind === 'html' && item.text.trim());
    const plain = children.find((item) => item.kind === 'plain' && item.text.trim());
    const firstBody = children.find((item) => item.text.trim());
    const attachments = children.flatMap((item) => item.attachments || []);
    return {
      kind: html?.kind || plain?.kind || firstBody?.kind || 'plain',
      text: html?.text || plain?.text || firstBody?.text || '',
      attachments,
    };
  }

  const decoded = decodeMimeBody(body, encoding);
  const disposition = headers['content-disposition'] || '';
  const filename = getMimeParameter(disposition, 'filename') || getMimeParameter(contentType, 'name');
  if (/attachment/i.test(disposition) || filename) {
    return { kind: 'attachment', text: '', attachments: filename ? [filename] : [] };
  }
  if (/text\/html/i.test(contentType)) return { kind: 'html', text: stripHtmlToText(decoded), attachments: [] };
  if (/text\//i.test(contentType)) return { kind: 'plain', text: decoded, attachments: [] };
  return { kind: 'plain', text: '', attachments: [] };
}

function cleanBodyText(text) {
  return String(text ?? '')
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .replace(/[ \t]+$/gm, '')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim();
}

export function parseEmlForGmailView(source) {
  const normalized = String(source ?? '').replace(/^\uFEFF/, '');
  const root = walkMime(normalized);
  const { headers } = splitHeadersBody(normalized);
  const top = parseHeaderBlock(headers);
  const fallbackFrom = top['return-path'] || top['sender'] || top['from'] || '';
  return {
    from: top['from'] || fallbackFrom || 'Unknown sender',
    to: top['to'] || '',
    cc: top['cc'] || '',
    bcc: top['bcc'] || '',
    replyTo: top['reply-to'] || '',
    subject: top['subject'] || '(no subject)',
    date: top['date'] || '',
    body: cleanBodyText(root.text),
    attachments: [...new Set(root.attachments || [])],
  };
}
