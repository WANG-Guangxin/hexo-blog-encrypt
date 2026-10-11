'use strict';

const PARTIAL_MARKER_RE = /<!--\s*(hbe-start\b[\s\S]*?|hbe-end)\s*-->/gi;
const PARTIAL_MESSAGE_RE = /^\s*<!--\s*hbe-message\s*:\s*([\s\S]*?)\s*-->\s*/i;
const MORE_MARKER_RE = /<!--\s*more\s*-->|<span\b[^>]*\bid\s*=\s*["']more["'][^>]*>\s*<\/span>/i;
const START_ATTRIBUTE_RE = /([a-z][a-z0-9-]*)\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/y;

function unescapeAttributeValue(value) {
  return value.replace(/\\([\\'"])/g, '$1');
}

function validateSingleLineValue(value, field) {
  if (/[\r\n]|-->/.test(value)) {
    throw new Error(
      `hexo-blog-encrypt: partial encryption ${field} must be a single-line value`
    );
  }
  return value;
}

function parseStartMarker(marker) {
  const spec = marker.slice('hbe-start'.length).trim();
  if (spec.startsWith(':')) {
    const password = validateSingleLineValue(spec.slice(1).trim(), 'password');
    if (!password) {
      throw new Error('hexo-blog-encrypt: partial encryption requires a password');
    }
    return {password, message: undefined};
  }

  if (!spec) {
    throw new Error('hexo-blog-encrypt: partial encryption requires a password');
  }

  const optionSpec = spec.trim();
  const options = Object.create(null);
  let cursor = 0;
  while (cursor < optionSpec.length) {
    while (/\s/.test(optionSpec[cursor])) cursor += 1;

    START_ATTRIBUTE_RE.lastIndex = cursor;
    const match = START_ATTRIBUTE_RE.exec(optionSpec);
    if (!match) {
      throw new Error(
        'hexo-blog-encrypt: partial encryption options must use quoted key="value" syntax'
      );
    }

    const name = match[1];
    if (name !== 'password' && name !== 'message') {
      throw new Error(`hexo-blog-encrypt: unknown partial encryption option "${name}"`);
    }
    if (Object.prototype.hasOwnProperty.call(options, name)) {
      throw new Error(`hexo-blog-encrypt: duplicate partial encryption option "${name}"`);
    }

    const quotedValue = match[2];
    const value = unescapeAttributeValue(quotedValue.slice(1, -1));
    options[name] = validateSingleLineValue(value, name);
    cursor = START_ATTRIBUTE_RE.lastIndex;
  }

  if (!options.password) {
    throw new Error('hexo-blog-encrypt: partial encryption requires a password');
  }
  return {password: options.password, message: options.message};
}

function parsePartialBlocks(html) {
  const source = String(html == null ? '' : html);
  const blocks = [];
  let open = null;
  let match;

  PARTIAL_MARKER_RE.lastIndex = 0;
  while ((match = PARTIAL_MARKER_RE.exec(source))) {
    const marker = match[1];
    if (marker.toLowerCase().startsWith('hbe-start')) {
      if (open) {
        throw new Error('hexo-blog-encrypt: partial encryption blocks cannot be nested');
      }

      const {password, message} = parseStartMarker(marker);

      open = {
        password,
        message,
        start: match.index,
        contentStart: PARTIAL_MARKER_RE.lastIndex,
      };

      const messageMatch = PARTIAL_MESSAGE_RE.exec(source.slice(open.contentStart));
      if (messageMatch) {
        if (open.message !== undefined) {
          throw new Error('hexo-blog-encrypt: partial encryption message is defined twice');
        }
        open.message = messageMatch[1].trim();
        open.contentStart += messageMatch[0].length;
      }
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
      message: open.message,
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

module.exports = {
  parsePartialBlocks,
  transformPartialBlocks,
};