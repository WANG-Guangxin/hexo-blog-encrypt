'use strict';

const PARTIAL_MARKER_RE = /<!--\s*(hbe-start\s*:\s*([\s\S]*?)|hbe-end)\s*-->/gi;
const MORE_MARKER_RE = /<!--\s*more\s*-->|<span\b[^>]*\bid\s*=\s*["']more["'][^>]*>\s*<\/span>/i;
const ATTR_ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
};

function parsePartialBlocks(html) {
  const source = String(html == null ? '' : html);
  const blocks = [];
  let open = null;
  let match;

  PARTIAL_MARKER_RE.lastIndex = 0;
  while ((match = PARTIAL_MARKER_RE.exec(source))) {
    const marker = match[1].toLowerCase();
    if (marker.startsWith('hbe-start')) {
      if (open) {
        throw new Error('hexo-blog-encrypt: partial encryption blocks cannot be nested');
      }

      const password = match[2].trim();
      if (!password) {
        throw new Error('hexo-blog-encrypt: partial encryption requires a password');
      }
      if (/[\r\n]|-->/.test(password)) {
        throw new Error(
          'hexo-blog-encrypt: partial encryption password must be a single-line value'
        );
      }

      open = {
        password,
        start: match.index,
        contentStart: PARTIAL_MARKER_RE.lastIndex,
      };
      continue;
    }

    if (!open) {
      throw new Error('hexo-blog-encrypt: partial encryption end marker has no start marker');
    }

    const content = source.slice(open.contentStart, match.index);
    if (MORE_MARKER_RE.test(content)) {
      throw new Error('hexo-blog-encrypt: a partial encryption block cannot cross <!-- more -->');
    }

    blocks.push({
      password: open.password,
      start: open.start,
      end: PARTIAL_MARKER_RE.lastIndex,
      contentStart: open.contentStart,
      contentEnd: match.index,
      content,
    });
    open = null;
  }

  if (open) {
    throw new Error('hexo-blog-encrypt: partial encryption start marker has no end marker');
  }

  return blocks;
}

function transformPartialBlocks(html, transform) {
  const source = String(html == null ? '' : html);
  const blocks = parsePartialBlocks(source);
  if (blocks.length === 0) {
    return { content: html, blocks };
  }

  let output = '';
  let cursor = 0;
  blocks.forEach((block, index) => {
    output += source.slice(cursor, block.start);
    output += transform(block.content, block.password, index, block);
    cursor = block.end;
  });
  output += source.slice(cursor);

  return { content: output, blocks };
}

function escapeAttr(value) {
  return String(value).replace(/[&<>"'`]/g, (character) => ATTR_ESCAPE_MAP[character]);
}

function escapeText(value) {
  return String(value).replace(/[&<>]/g, (character) => {
    if (character === '&') return '&amp;';
    if (character === '<') return '&lt;';
    return '&gt;';
  });
}

function renderPartialContainer(opts) {
  const buttonClass = opts.buttonShow === false ? ' hbe-button-hidden' : '';
  return [
    '<div class="hbe hbe-container hbe-partial-container" data-hbe-partial="true"',
    ` data-hbe-format="${escapeAttr(opts.format)}"`,
    ` data-wpm="${escapeAttr(opts.wpm)}"`,
    ` data-whm="${escapeAttr(opts.whm)}"`,
    ` data-salt="${escapeAttr(opts.saltHex)}"`,
    ` data-nonce="${escapeAttr(opts.nonceHex)}"`,
    ` data-kdf-iterations="${escapeAttr(opts.kdfIterations)}"`,
    ' data-auto-save="false"',
    '>',
    `  <script type="application/octet-stream" data-hbe-partial-data>${escapeText(opts.ciphertextHex)}</script>`,
    '  <div class="hbe hbe-content">',
    '    <form class="hbe hbe-form" data-hbe-partial-form onsubmit="return false">',
    '      <div class="hbe hbe-input hbe-input-default">',
    '        <input class="hbe hbe-input-field hbe-input-field-default hbe-partial-password"',
    '               type="password" autocomplete="off">',
    '        <label class="hbe hbe-input-label hbe-input-label-default">',
    `          <span class="hbe hbe-input-label-content hbe-input-label-content-default">${escapeText(opts.message)}</span>`,
    '        </label>',
    '      </div>',
    `      <button class="hbe hbe-button${buttonClass}" type="submit">${escapeText(opts.buttonText)}</button>`,
    '      <div class="hbe hbe-error" role="alert" aria-live="polite"></div>',
    '    </form>',
    '  </div>',
    '</div>',
  ].join('\n');
}

module.exports = {
  parsePartialBlocks,
  transformPartialBlocks,
  renderPartialContainer,
};