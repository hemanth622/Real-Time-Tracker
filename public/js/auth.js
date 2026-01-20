document.addEventListener('DOMContentLoaded', () => {
    // Check if user is already logged in
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
        // Check if user is trying to join a room directly
        const urlParams = new URLSearchParams(window.location.search);
        const roomId = urlParams.get('roomId');
        
        if (roomId) {
            // Redirect to the room
            window.location.href = `/tracker/${roomId}`;
        } else {
            // Redirect to dashboard
            window.location.href = '/dashboard';
        }
    }
    
    // Tab switching functionality
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to current tab
            tab.classList.add('active');
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Toggle password visibility
    document.querySelectorAll('.toggle-password').forEach(button => {
        button.addEventListener('click', function() {
            const passwordInput = this.parentElement.querySelector('input');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        });
    });
    
    // Feature icon animations
    const featureIcons = document.querySelectorAll('.feature-icon');
    
    // Add hover effect
    featureIcons.forEach(icon => {
        icon.addEventListener('mouseover', () => {
            icon.style.transform = 'translateY(-8px)';
            icon.style.transition = 'transform 0.3s ease';
        });
        
        icon.addEventListener('mouseout', () => {
            icon.style.transform = 'translateY(0)';
        });
    });
    
    // Animate icons on page load
    const animateFeatures = document.querySelectorAll('.animate-feature');
    animateFeatures.forEach((feature, index) => {
        setTimeout(() => {
            feature.style.opacity = '1';
            feature.style.transform = 'translateY(0)';
        }, 200 * (index + 1));
    });
    
    // Login form submission
    const loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;
        
        if (!email || !password) {
            alert('Email and password are required!');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store user data in localStorage (token is kept in HttpOnly cookie)
                localStorage.setItem('user', JSON.stringify(data.user));
                
                // Check if user was trying to join a room
                const urlParams = new URLSearchParams(window.location.search);
                const roomId = urlParams.get('roomId');
                
                if (roomId) {
                    // Redirect to the room
                    window.location.href = `/tracker/${roomId}`;
                } else {
                    // Redirect to dashboard
                    window.location.href = '/dashboard';
                }
            } else {
                alert(data.message || 'Login failed. Please check your credentials.');
            }
        } catch (error) {
            console.error('Login error:', error);
            alert('An error occurred during login. Please try again.');
        }
    });
    
    // Registration form submission
    const registerForm = document.getElementById('register-form');
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('register-email').value.trim();
        const username = document.getElementById('register-username').value.trim();
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm').value;
        
        if (!email || !username || !password) {
            alert('Email, display name, and password are required!');
            return;
        }
        
        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    email, 
                    username, 
                    password 
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                alert('Registration successful! Please log in.');
                
                // Switch to login tab
                tabs[0].click();
                
                // Pre-fill email
                document.getElementById('login-email').value = email;
            } else {
                alert(data.message || 'Registration failed. Please try again.');
            }
        } catch (error) {
            console.error('Registration error:', error);
            alert('An error occurred during registration. Please try again.');
        }
    });
    
    // Guest join form submission
    const guestJoinForm = document.getElementById('guest-join-form');
    guestJoinForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const roomId = document.getElementById('guest-room-id').value.trim();
        const guestName = document.getElementById('guest-name').value.trim();
        
        if (!roomId || !guestName) {
            alert('Room ID and display name are required!');
            return;
        }
        
        // Store guest info in sessionStorage (temporary)
        sessionStorage.setItem('guestName', guestName);
        sessionStorage.setItem('isGuest', 'true');
        
        // Redirect to tracker page with room ID
        window.location.href = `/tracker/${roomId}?guest=true`;
    });
}); 