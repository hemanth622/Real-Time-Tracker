document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const room = document.getElementById('room').value.trim();
        
        if (!username || !room) {
            alert('Username and Room ID are required!');
            return;
        }
        
        // Store user data in sessionStorage
        sessionStorage.setItem('username', username);
        sessionStorage.setItem('room', room);
        
        // Redirect to tracker page
        window.location.href = `/tracker?username=${encodeURIComponent(username)}&room=${encodeURIComponent(room)}`;
    });
}); 