'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  parsePartialBlocks,
  transformPartialBlocks,
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

test('parsePartialBlocks reads a per-block message outside the ciphertext', () => {
  const blocks = parsePartialBlocks([
    '<!-- hbe-start:secret -->',
    '<!-- hbe-message: Enter this block password -->',
    '<p>secret</p>',
    '<!-- hbe-end -->',
  ].join('\n'));

  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].message, 'Enter this block password');
  assert.equal(blocks[0].content, '<p>secret</p>\n');
});

test('parsePartialBlocks supports structured password and message options', () => {
  const blocks = parsePartialBlocks([
    '<!-- hbe-start password="secret:with:colon" message="Enter: this block password" -->',
    '<p>secret</p>',
    '<!-- hbe-end -->',
  ].join('\n'));

  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].password, 'secret:with:colon');
  assert.equal(blocks[0].message, 'Enter: this block password');
  assert.equal(blocks[0].content, '\n<p>secret</p>\n');
});

test('parsePartialBlocks rejects malformed or unknown structured options', () => {
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start message="missing password" -->secret<!-- hbe-end -->'),
    /requires a password/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start -->secret<!-- hbe-end -->'),
    /requires a password/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start password="pw" theme="blink" -->secret<!-- hbe-end -->'),
    /unknown partial encryption option "theme"/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start password="pw" password="again" -->secret<!-- hbe-end -->'),
    /duplicate partial encryption option "password"/
  );
  assert.throws(
    () => parsePartialBlocks('<!-- hbe-start password=pw -->secret<!-- hbe-end -->'),
    /quoted key="value" syntax/
  );
  assert.throws(
    () => parsePartialBlocks([
      '<!-- hbe-start password="pw" message="inline" -->',
      '<!-- hbe-message:legacy -->',
      'secret',
      '<!-- hbe-end -->',
    ].join('\n')),
    /message is defined twice/
  );
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

test('transformPartialBlocks leaves content unchanged when there are no blocks', () => {
  const result = transformPartialBlocks('<p>public</p>', () => {
    throw new Error('transform must not run without partial blocks');
  });

  assert.equal(result.content, '<p>public</p>');
  assert.deepEqual(result.blocks, []);
});

test('transformPartialBlocks treats null input as empty content', () => {
  const result = transformPartialBlocks(null, () => {
    throw new Error('transform must not run without partial blocks');
  });

  assert.equal(result.content, null);
  assert.deepEqual(result.blocks, []);
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
