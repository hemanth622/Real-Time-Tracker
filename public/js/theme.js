// Theme management functionality
document.addEventListener('DOMContentLoaded', function() {
    // Find the theme toggle button
    const themeToggle = document.getElementById('theme-toggle-btn');
    
    // If the button doesn't exist, don't proceed
    if (!themeToggle) {
        console.error('Theme toggle button not found');
        return;
    }
    
    // Check for saved theme preference or default to dark theme
    const savedTheme = localStorage.getItem('theme') || 'dark-theme';
    document.body.classList.add(savedTheme);
    
    // Update toggle button icon based on current theme
    updateThemeToggleIcon(savedTheme);
    
    // Add click event to toggle theme
    themeToggle.addEventListener('click', function() {
        if (document.body.classList.contains('dark-theme')) {
            document.body.classList.replace('dark-theme', 'light-theme');
            localStorage.setItem('theme', 'light-theme');
            updateThemeToggleIcon('light-theme');
        } else {
            document.body.classList.replace('light-theme', 'dark-theme');
            localStorage.setItem('theme', 'dark-theme');
            updateThemeToggleIcon('dark-theme');
        }
    });
    
    // Function to update the toggle icon based on current theme
    function updateThemeToggleIcon(theme) {
        if (theme === 'light-theme') {
            themeToggle.innerHTML = '<i class="bi bi-sun-fill"></i>';
        } else {
            themeToggle.innerHTML = '<i class="bi bi-moon-fill"></i>';
        }
    }
}); 