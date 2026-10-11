'use strict';

// DOM helpers preserved from v3 (`getExecutableScript` + `convertHTMLToElement`):
// when ciphertext decrypts to HTML containing `<script>` tags, the browser does
// NOT execute scripts inserted via `innerHTML`. We re-create them as live <script>
// elements so the decrypted post behaves like a normal Hexo-rendered post.

function getExecutableScript(oldScriptElement) {
  const newScript = document.createElement('script');
  for (const attr of oldScriptElement.attributes) {
    newScript.setAttribute(attr.name, attr.value);
  }
  newScript.text = oldScriptElement.text;
  return newScript;
}

function convertHTMLToElement(htmlString) {
  const wrapper = document.createElement('div');
  wrapper.innerHTML = htmlString;
  // Collect all <script> elements and replace them with placeholders so we
  // can re-insert them one-by-one while preserving DOM position.
  const scripts = Array.from(wrapper.querySelectorAll('script'));
  if (scripts.length === 0) return wrapper;

  const items = scripts.map((oldScript) => {
    const placeholder = document.createElement('div');
    oldScript.parentNode.replaceChild(placeholder, oldScript);
    return { placeholder, oldScript };
  });

  // Process scripts sequentially to preserve load / execute order.
  // External scripts (<script src="...">) created via createElement()
  // load asynchronously — without this sequential guard, inline scripts
  // that depend on them would run before the library finishes loading.
  function loadNext(index) {
    if (index >= items.length) return;
    const { placeholder, oldScript } = items[index];
    const newScript = getExecutableScript(oldScript);
    if (newScript.src) {
      // External script — wait for load before processing the next one.
      newScript.onload = () => loadNext(index + 1);
      newScript.onerror = () => loadNext(index + 1);
      placeholder.parentNode.replaceChild(newScript, placeholder);
    } else {
      // Inline script — executes synchronously when inserted.
      placeholder.parentNode.replaceChild(newScript, placeholder);
      loadNext(index + 1);
    }
  }

  loadNext(0);
  return wrapper;
}

// Replace the encrypted wrapper with the decrypted DOM. Returns the new container
// so callers can inspect / dispatch events on it.
function swapInDecryptedDOM(mainElement, plaintextHTML) {
  const decrypted = convertHTMLToElement(plaintextHTML);
  decrypted.id = 'hexo-blog-encrypt';
  decrypted.classList.add('hbe', 'hbe-decrypted-content');
  mainElement.parentNode.replaceChild(decrypted, mainElement);
  return decrypted;
}

function replaceElementWithDecryptedDOM(mainElement, plaintextHTML) {
  const decrypted = convertHTMLToElement(plaintextHTML);
  decrypted.classList.add('hbe', 'hbe-decrypted-content', 'hbe-partial-decrypted-content');
  mainElement.parentNode.replaceChild(decrypted, mainElement);
}

module.exports = {
  getExecutableScript,
  convertHTMLToElement,
  swapInDecryptedDOM,
  replaceElementWithDecryptedDOM,
};
