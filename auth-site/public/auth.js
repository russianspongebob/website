const form = document.getElementById('form');
const msg = document.getElementById('msg');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  msg.textContent = '';
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const res = await fetch(form.dataset.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');
    window.location.href = '/dashboard';
  } catch (err) {
    msg.textContent = err.message;
    button.disabled = false;
  }
});
