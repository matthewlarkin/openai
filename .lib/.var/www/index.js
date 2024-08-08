// on document load
document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    });

    setInterval(() => {
        document.querySelector('body').setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    }, 60000);

    // Check if the View Transitions API is supported
    if (document.startViewTransition) {
        document.startViewTransition(() => {
            document.body.classList.add('fade-in');
        });
    } else {
        // Fallback for browsers that do not support the View Transitions API
        document.body.classList.add('fade-in');
    }
});