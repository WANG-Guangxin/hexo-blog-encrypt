'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  parsePartialBlocks,
  transformPartialBlocks,
  renderPartialContainer,
} = require('../../src/server/partial');

test('parsePartialBlocks returns each password and plaintext range', () => {
  const html = [
    '<p>public</p>',
    '<!-- hbe-start: first password -->',
    '<p>first</p>',
    '<!-- hbe-end -->',
    '<p>middle</p>',
    '<!-- hbe-start:second-->',
    '<p>second</p>',
    '<!-- hbe-end -->',
  ].join('\n');

  const blocks = parsePartialBlocks(html);

  assert.equal(blocks.length, 2);
  assert.equal(blocks[0].password, 'first password');
  assert.equal(blocks[0].content, '\n<p>first</p>\n');
  assert.equal(blocks[1].password, 'second');
  assert.equal(blocks[1].content, '\n<p>second</p>\n');
});

test('transformPartialBlocks replaces markers and preserves public content', () => {
  const html = 'before<!-- hbe-start:pw -->secret<!-- hbe-end -->after';

  const result = transformPartialBlocks(html, (content, password, index) =>
    `<private data-password="${password}" data-index="${index}">${content}</private>`
  );

  assert.equal(
    result.content,
    'before<private data-password="pw" data-index="0">secret</private>after'
  );
  assert.equal(result.blocks.length, 1);
});

test('markers inside escaped code are ordinary text', () => {
  const html = '<pre><code>&lt;!-- hbe-start:pw --&gt;secret&lt;!-- hbe-end --&gt;</code></pre>';

  assert.deepEqual(parsePartialBlocks(html), []);
});

test('nested blocks are rejected', () => {
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start:one --><!-- hbe-start:two --><!-- hbe-end -->'),
    /cannot be nested/
  );
});

test('unbalanced blocks are rejected', () => {
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-end -->'),
    /has no start marker/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start:pw -->secret'),
    /has no end marker/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start: -->secret<!-- hbe-end -->'),
    /requires a password/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start:line\nbreak -->secret<!-- hbe-end -->'),
    /single-line value/
  );
});

test('a block cannot cross the rendered more marker', () => {
  assert.throws(
    () => parsePartialBlocks(
      '<!-- hbe-start:pw -->secret<span id="more"></span>still secret<!-- hbe-end -->'
    ),
    /cannot cross <!-- more -->/
  );

  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start:pw -->secret<!-- more -->still secret<!-- hbe-end -->'),
    /cannot cross <!-- more -->/
  );
});

test('renderPartialContainer escapes UI text and keeps ciphertext in a data node', () => {
  const html = renderPartialContainer({
    format: '4',
    saltHex: 'aa',
    nonceHex: 'bb',
    ciphertextHex: 'cc',
    kdfIterations: 250000,
    message: '<message>',
    wpm: '" onmouseover="alert(1)',
    whm: 'wrong',
    buttonShow: false,
    buttonText: '<open>',
  });

  assert.match(html, /data-hbe-partial="true"/);
  assert.match(html, /data-hbe-partial-data>cc<\/script>/);
  assert.match(html, /data-wpm="&quot; onmouseover=&quot;alert\(1\)"/);
  assert.match(html, /&lt;message&gt;/);
  assert.match(html, /&lt;open&gt;/);
  assert.doesNotMatch(html, /data-hbe-ciphertext=/);
  assert.match(html, /hbe-button-hidden/);
});