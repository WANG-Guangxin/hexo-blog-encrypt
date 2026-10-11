'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { buildSite } = require('../helpers/buildSite.js');

const ITERATIONS = 100000;

function decryptPayload({ password, saltHex, nonceHex, ciphertextHex, iterations }) {
  const salt = Buffer.from(saltHex, 'hex');
  const nonce = Buffer.from(nonceHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');
  const key = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const tag = ciphertext.subarray(ciphertext.length - 16);
  const encrypted = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function extractPayloads(html) {
  return Array.from(html.matchAll(
    /<div class="hbe hbe-container hbe-partial-container"[^>]*data-salt="([0-9a-f]+)"[^>]*data-nonce="([0-9a-f]+)"[^>]*data-kdf-iterations="([0-9]+)"[^>]*>[\s\S]*?<script type="application\/octet-stream" data-hbe-partial-data>([0-9a-f]+)<\/script>/gi
  )).map((match) => ({
    saltHex: match[1],
    nonceHex: match[2],
    iterations: Number(match[3]),
    ciphertextHex: match[4],
  }));
}

function partialData(content, overrides) {
  return Object.assign({
    title: 'partial',
    content,
    theme: 'default',
    silent: true,
  }, overrides || {});
}

let hexo;

before(async () => {
  hexo = await buildSite();
});

after(async () => {
  if (hexo) await hexo.exit();
});

test('partial encryption removes markers and plaintext from generated HTML', async () => {
  hexo.config.encrypt = { kdf: { iterations: ITERATIONS } };
  const data = partialData([
    '<p>public</p>',
    '<!-- hbe-start:secret -->',
    '<p>THE PARTIAL SECRET</p>',
    '<!-- hbe-end -->',
    '<p>after</p>',
  ].join('\n'));

  await hexo.execFilter('after_post_render', data, { context: hexo });

  assert.equal(data.encrypt, undefined);
  assert.equal(data.partial_encrypt, true);
  assert.equal((data.content.match(/data-hbe-partial="true"/g) || []).length, 1);
  assert.equal(data.content.includes('data-hbe-ciphertext='), false);
  assert.equal(data.content.includes('THE PARTIAL SECRET'), false);
  assert.equal(data.content.includes('hbe-start'), false);
  assert.equal(data.content.includes('hbe-end'), false);

  const [payload] = extractPayloads(data.content);
  assert.equal(decryptPayload({ password: 'secret', ...payload }), '\n<p>THE PARTIAL SECRET</p>\n');
});

test('independent language blocks produce independent decryptable payloads', async () => {
  hexo.config.encrypt = { kdf: { iterations: ITERATIONS } };
  const data = partialData([
    '<div lang="zh-CN">',
    '<p>公开中文</p>',
    '<!-- hbe-start:shared -->',
    '<p>中文秘密</p>',
    '<!-- hbe-end -->',
    '</div>',
    '<div lang="en">',
    '<p>public English</p>',
    '<!-- hbe-start:shared -->',
    '<p>English secret</p>',
    '<!-- hbe-end -->',
    '</div>',
  ].join('\n'));

  await hexo.execFilter('after_post_render', data, { context: hexo });

  const payloads = extractPayloads(data.content);
  assert.equal(payloads.length, 2);
  assert.notEqual(payloads[0].saltHex, payloads[1].saltHex);
  assert.equal(decryptPayload({ password: 'shared', ...payloads[0] }).includes('中文秘密'), true);
  assert.equal(decryptPayload({ password: 'shared', ...payloads[1] }).includes('English secret'), true);
  assert.equal(data.content.includes('中文秘密'), false);
  assert.equal(data.content.includes('English secret'), false);
});

test('partial stableSalt reuses salt but keeps nonce fresh', async () => {
  hexo.config.encrypt = { kdf: { iterations: ITERATIONS }, stableSalt: true };
  const opts = {
    title: 'partial-stable',
    content: '<!-- hbe-start:secret -->\n<p>stable partial</p>\n<!-- hbe-end -->',
    permalink: 'https://example.test/partial-stable/',
  };
  const first = partialData(opts.content, opts);
  const second = partialData(opts.content, opts);

  await hexo.execFilter('after_post_render', first, { context: hexo });
  await hexo.execFilter('after_post_render', second, { context: hexo });

  const firstPayload = extractPayloads(first.content)[0];
  const secondPayload = extractPayloads(second.content)[0];
  assert.equal(firstPayload.saltHex, secondPayload.saltHex);
  assert.notEqual(firstPayload.nonceHex, secondPayload.nonceHex);
  assert.equal(
    decryptPayload({ password: 'secret', ...firstPayload }),
    '\n<p>stable partial</p>\n'
  );
  assert.equal(
    decryptPayload({ password: 'secret', ...secondPayload }),
    '\n<p>stable partial</p>\n'
  );
});

test('partial markers cannot cross the more boundary in the filter pipeline', async () => {
  hexo.config.encrypt = {};
  const data = partialData([
    '<!-- hbe-start:secret -->',
    '<p>secret excerpt</p>',
    '<!-- more -->',
    '<p>secret body</p>',
    '<!-- hbe-end -->',
  ].join('\n'));

  await assert.rejects(
    hexo.execFilter('after_post_render', data, { context: hexo }),
    /cannot cross <!-- more -->/
  );
});

test('partial and full-post encryption cannot be combined', async () => {
  hexo.config.encrypt = {};
  const data = partialData(
    '<!-- hbe-start:secret -->secret<!-- hbe-end -->',
    { password: 'whole-post' }
  );

  await assert.rejects(
    hexo.execFilter('after_post_render', data, { context: hexo }),
    /cannot combine full-post and partial encryption/
  );
});

test('partial encryption conflicts with a globally configured full-post password', async () => {
  hexo.config.encrypt = { password: 'whole-post' };
  const data = partialData(
    '<!-- hbe-start:secret -->secret<!-- hbe-end -->'
  );

  await assert.rejects(
    hexo.execFilter('after_post_render', data, { context: hexo }),
    /cannot combine full-post and partial encryption/
  );
});

test('an empty front-matter password does not disable partial encryption', async () => {
  hexo.config.encrypt = {};
  const data = partialData(
    '<!-- hbe-start:secret -->secret<!-- hbe-end -->',
    { password: '' }
  );

  await hexo.execFilter('after_post_render', data, { context: hexo });

  assert.equal(data.partial_encrypt, true);
});

test('partial encryption conflicts with a matching encrypted tag', async () => {
  hexo.config.encrypt = {
    tags: [{ name: 'Secret', password: 'whole-post' }],
  };
  const data = partialData(
    '<!-- hbe-start:secret -->secret<!-- hbe-end -->',
    { tags: [{ name: 'Secret' }] }
  );

  await assert.rejects(
    hexo.execFilter('after_post_render', data, { context: hexo }),
    /cannot combine full-post and partial encryption/
  );
});

test('partial encryption falls back for non-string button text and title', async () => {
  hexo.config.encrypt = {
    decryptButton: { text: 12345 },
  };
  const data = partialData(
    '<!-- hbe-start:secret -->secret<!-- hbe-end -->',
    { title: 12345 }
  );

  await hexo.execFilter('after_post_render', data, { context: hexo });

  assert.equal(data.partial_encrypt, true);
  assert.match(data.content, />Decrypt<\/button>/);
});
