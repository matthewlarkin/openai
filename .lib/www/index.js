

document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
});

setInterval(() => {
  document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}, 60000);