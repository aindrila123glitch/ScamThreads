// Home Page Quick Action
import { initNav } from '../shared.js';

initNav();

const quickForm = document.getElementById('quick-link-form');
const quickInput = document.getElementById('quick-url-input');

if (quickForm && quickInput) {
  quickForm.addEventListener('submit', event => {
    event.preventDefault();
    const url = quickInput.value.trim();
    if (url) {
      window.location.href = '/link?u=' + encodeURIComponent(url);
    }
  });
}
