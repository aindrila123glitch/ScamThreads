// Help page script
import { initNav } from '../shared.js';

initNav();

// Allow users to click items in the recovery checklist to strike them through
const items = document.querySelectorAll('#checklist-items li');
items.forEach(li => {
  li.style.cursor = 'pointer';
  li.addEventListener('click', () => {
    if (li.style.textDecoration === 'line-through') {
      li.style.textDecoration = 'none';
      li.style.opacity = '1';
    } else {
      li.style.textDecoration = 'line-through';
      li.style.opacity = '0.6';
    }
  });
});
