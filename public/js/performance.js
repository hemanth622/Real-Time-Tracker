// Basic functionality fixes
document.addEventListener('DOMContentLoaded', function() {
  // Fix Bootstrap components
  if (typeof bootstrap !== 'undefined') {
    // Initialize dropdowns
    document.querySelectorAll('.dropdown-toggle').forEach(el => {
      new bootstrap.Dropdown(el);
    });
  }
  
  // Fix room creation with direct navigation
  const createRoomForm = document.getElementById('create-room-form');
  if (createRoomForm) {
    createRoomForm.addEventListener('submit', function(e) {
      e.preventDefault();
      
      // Show loading state
      const submitBtn = document.getElementById('create-room-submit');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Creating...';
      }
      
      const roomName = document.getElementById('room-name').value.trim();
      if (!roomName) {
        alert('Room name is required');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Create Room';
        }
        return;
      }
      
      const token = localStorage.getItem('token');
      if (!token) {
        window.location.href = '/';
        return;
      }
      
      // Close modal if open
      const modal = document.getElementById('createRoomModal');
      if (modal && typeof bootstrap !== 'undefined') {
        const modalInstance = bootstrap.Modal.getInstance(modal);
        if (modalInstance) modalInstance.hide();
      }
      
      // Direct API call without fetch for better reliability
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/rooms/create', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      
      xhr.onload = function() {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const response = JSON.parse(xhr.responseText);
            if (response.room && response.room.id) {
              // Redirect to dashboard instead of tracker page
              alert('Room created successfully! Room ID: ' + response.room.id);
              window.location.href = '/dashboard';
            } else {
              alert('Failed to create room. Please try again.');
              if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Create Room';
              }
            }
          } catch (e) {
            alert('Error processing response. Please try again.');
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = 'Create Room';
            }
          }
        } else {
          alert('Failed to create room. Please try again.');
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Create Room';
          }
        }
      };
      
      xhr.onerror = function() {
        alert('Network error. Please try again.');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Create Room';
        }
      };
      
      xhr.send(JSON.stringify({
        name: roomName,
        description: document.getElementById('room-description').value.trim()
      }));
    });
  }
  
  // Fix room entry buttons using event delegation
  document.addEventListener('click', function(e) {
    // Check if the clicked element is an enter button or has a parent that is
    const enterButton = e.target.closest('.enter-room, [id^="Enter"]');
    
    if (enterButton) {
      console.log('Enter button clicked via delegation');
      e.preventDefault();
      e.stopPropagation();
      
      // Prevent multiple clicks
      if (enterButton.disabled) {
        console.log('Button is disabled, ignoring click');
        return;
      }
      
      // Disable button to prevent double clicks
      enterButton.disabled = true;
      
      // Store original text
      const originalText = enterButton.innerHTML;
      enterButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Entering...';
      
      // Get room ID
      let roomId = enterButton.getAttribute('data-room-id');
      console.log('Room ID from attribute:', roomId);
      
      if (!roomId) {
        // Try to get room ID from parent elements
        const roomCard = enterButton.closest('.room-card');
        console.log('Room card found:', !!roomCard);
        
        if (roomCard && roomCard.dataset.roomId) {
          roomId = roomCard.dataset.roomId;
          console.log('Room ID from parent:', roomId);
        } else {
          console.error('Room ID not found');
          enterButton.disabled = false;
          enterButton.innerHTML = originalText;
          return;
        }
      }
      
      // Navigate to room
      console.log('Navigating to:', `/tracker/${roomId}`);
      window.location.href = `/tracker/${roomId}`;
    }
  });
  
  // Fix logout
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function() {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/';
    });
  }
  
  // Fix guest room joining
  const guestForm = document.getElementById('guest-join-form');
  if (guestForm) {
    guestForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const roomId = document.getElementById('guest-room-id').value.trim();
      const guestName = document.getElementById('guest-name').value.trim();
      
      if (!roomId) {
        alert('Room ID is required');
        return;
      }
      
      if (!guestName) {
        alert('Your name is required');
        return;
      }
      
      // Store guest name in session storage
      sessionStorage.setItem('guestName', guestName);
      
      // Navigate to tracker page as guest
      window.location.href = `/tracker/${roomId}?guest=true`;
    });
  }
}); 