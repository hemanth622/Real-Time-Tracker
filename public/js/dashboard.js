// Performance optimized dashboard.js
document.addEventListener('DOMContentLoaded', async () => {
    // Cache DOM elements for better performance
    const elements = {
        usernameDisplay: document.getElementById('username-display'),
        welcomeUsername: document.getElementById('welcome-username'),
        profileUsername: document.getElementById('profile-username'),
        profileEmail: document.getElementById('profile-email'),
        logoutBtn: document.getElementById('logout-btn'),
        createRoomForm: document.getElementById('create-room-form'),
        joinRoomForm: document.getElementById('join-room-form'),
        joinRoomId: document.getElementById('join-room-id'),
        roomName: document.getElementById('room-name'),
        roomDescription: document.getElementById('room-description'),
        myRooms: document.getElementById('my-rooms'),
        joinedRooms: document.getElementById('joined-rooms'),
        myRoomsCount: document.getElementById('my-rooms-count'),
        joinedRoomsCount: document.getElementById('joined-rooms-count'),
        noRoomsMessage: document.getElementById('no-rooms-message'),
        noJoinedRoomsMessage: document.getElementById('no-joined-rooms-message')
    };

    // Check if user is logged in (user stored in localStorage, JWT in HttpOnly cookie)
    const user = JSON.parse(localStorage.getItem('user') || 'null');
    
    if (!user || !user.id) {
        // Redirect to login page if not logged in
        window.location.href = '/';
        return;
    }
    
    // Display username
    if (elements.usernameDisplay) elements.usernameDisplay.textContent = user.username;
    if (elements.welcomeUsername) elements.welcomeUsername.textContent = user.username;
    
    // Profile info
    if (elements.profileUsername) elements.profileUsername.textContent = user.username;
    if (elements.profileEmail) elements.profileEmail.textContent = user.email;
    
    // Fix logout functionality - Direct implementation
    function handleLogout() {
        localStorage.removeItem('user');
        // Also clear HttpOnly cookie on server
        fetch('/api/auth/logout', { method: 'POST' }).finally(() => {
            window.location.href = '/';
        });
    }
    
    // Add logout handler
    if (elements.logoutBtn) {
        elements.logoutBtn.onclick = handleLogout;
    }
    
    // Fetch rooms
    async function fetchRooms() {
        try {
            const response = await fetch('/api/rooms');
            
            if (!response.ok) {
                throw new Error('Failed to fetch rooms');
            }
            
            const data = await response.json();
            
            // Clear rooms containers
            if (elements.myRooms) elements.myRooms.innerHTML = '';
            if (elements.joinedRooms) elements.joinedRooms.innerHTML = '';
            
            // Add rooms to UI
            if (data.myRooms && data.myRooms.length > 0 && elements.myRooms) {
                data.myRooms.forEach(room => {
                    const roomElement = createRoomElement(room, true);
                    elements.myRooms.appendChild(roomElement);
                });
                if (elements.noRoomsMessage) elements.noRoomsMessage.style.display = 'none';
            } else {
                if (elements.noRoomsMessage) elements.noRoomsMessage.style.display = 'block';
            }
            
            if (data.joinedRooms && data.joinedRooms.length > 0 && elements.joinedRooms) {
                data.joinedRooms.forEach(room => {
                    const roomElement = createRoomElement(room, false);
                    elements.joinedRooms.appendChild(roomElement);
                });
                if (elements.noJoinedRoomsMessage) elements.noJoinedRoomsMessage.style.display = 'none';
            } else {
                if (elements.noJoinedRoomsMessage) elements.noJoinedRoomsMessage.style.display = 'block';
            }
            
            // Update counts
            updateRoomCounts();
            
        } catch (error) {
            console.error('Fetch rooms error:', error);
        }
    }
    
    // Create room element
    function createRoomElement(room, isOwner) {
        console.log('Creating room element:', room.id, room.name);
        
        const roomDiv = document.createElement('div');
        roomDiv.className = 'room-card';
        roomDiv.dataset.roomId = room.id;
        
        const roomHeader = document.createElement('div');
        roomHeader.className = 'd-flex justify-content-between align-items-center mb-2';
        
        const roomTitle = document.createElement('h3');
        roomTitle.textContent = room.name;
        roomHeader.appendChild(roomTitle);
        
        if (isOwner) {
            const ownerBadge = document.createElement('span');
            ownerBadge.className = 'badge bg-primary';
            ownerBadge.textContent = 'Owner';
            roomHeader.appendChild(ownerBadge);
        }
        
        roomDiv.appendChild(roomHeader);
        
        if (room.description) {
            const roomDesc = document.createElement('p');
            roomDesc.textContent = room.description;
            roomDiv.appendChild(roomDesc);
        }
        
        const roomInfo = document.createElement('div');
        roomInfo.className = 'room-info';
        
        const roomId = document.createElement('span');
        roomId.textContent = `ID: ${room.id}`;
        roomInfo.appendChild(roomId);
        
        const roomDate = document.createElement('span');
        roomDate.textContent = new Date(room.createdAt).toLocaleDateString();
        roomInfo.appendChild(roomDate);
        
        roomDiv.appendChild(roomInfo);
        
        const roomActions = document.createElement('div');
        roomActions.className = 'room-actions mt-3';
        
        const enterBtn = document.createElement('button');
        enterBtn.className = 'btn btn-sm btn-primary enter-room';
        enterBtn.innerHTML = '<i class="bi bi-box-arrow-in-right me-1"></i>Enter';
        enterBtn.dataset.roomId = room.id;
        enterBtn.addEventListener('click', () => {
            window.location.href = `/tracker/${room.id}`;
        });
        
        roomActions.appendChild(enterBtn);
        
        const shareBtn = document.createElement('button');
        shareBtn.className = 'btn btn-sm btn-outline-primary';
        shareBtn.innerHTML = '<i class="bi bi-share me-1"></i>Share';
        shareBtn.addEventListener('click', () => {
            // Copy room ID to clipboard
            navigator.clipboard.writeText(room.id).then(() => {
                alert(`Room ID ${room.id} copied to clipboard!`);
            });
        });
        roomActions.appendChild(shareBtn);
        
        if (isOwner) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-sm btn-outline-danger';
            deleteBtn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete';
            deleteBtn.addEventListener('click', async () => {
                if (confirm(`Are you sure you want to delete room "${room.name}"?`)) {
                    try {
                        const response = await fetch(`/api/rooms/${room.id}`, {
                            method: 'DELETE'
                        });
                        
                        if (response.ok) {
                            roomDiv.remove();
                            updateRoomCounts();
                            
                            // Show no rooms message if no rooms left
                            if (elements.myRooms && elements.myRooms.children.length === 0 && elements.noRoomsMessage) {
                                elements.noRoomsMessage.style.display = 'block';
                            }
                        } else {
                            const data = await response.json();
                            alert(data.message || 'Failed to delete room. Please try again.');
                        }
                    } catch (error) {
                        console.error('Delete room error:', error);
                        alert('An error occurred while deleting the room. Please try again.');
                    }
                }
            });
            roomActions.appendChild(deleteBtn);

            const inviteBtn = document.createElement('button');
            inviteBtn.className = 'btn btn-sm btn-outline-secondary ms-2';
            inviteBtn.innerHTML = '<i class="bi bi-link-45deg me-1"></i>Invite Link';
            inviteBtn.addEventListener('click', async () => {
                try {
                    const res = await fetch(`/api/rooms/${room.id}/invite`);
                    const data = await res.json();
                    if (!res.ok) {
                        alert(data.message || 'Failed to create invite link');
                        return;
                    }
                    const fullUrl = `${window.location.origin}${data.inviteUrl}`;
                    await navigator.clipboard.writeText(fullUrl);
                    alert('Invite link copied to clipboard!');
                } catch (err) {
                    console.error('Invite link error:', err);
                    alert('Failed to create invite link');
                }
            });
            roomActions.appendChild(inviteBtn);
        }
        
        roomDiv.appendChild(roomActions);
        
        return roomDiv;
    }
    
    // Update room counts
    function updateRoomCounts() {
        if (elements.myRoomsCount && elements.myRooms) {
            elements.myRoomsCount.textContent = elements.myRooms.children.length;
        }
        if (elements.joinedRoomsCount && elements.joinedRooms) {
            elements.joinedRoomsCount.textContent = elements.joinedRooms.children.length;
        }
    }
    
    // Handle join room form submission
    if (elements.joinRoomForm) {
        elements.joinRoomForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!elements.joinRoomId) return;
            
            const roomId = elements.joinRoomId.value.trim().toUpperCase();
            
            if (!roomId || roomId.length !== 6) {
                alert('Please enter a valid 6-character room ID.');
                return;
            }
            
            try {
                // First try to fetch room details to verify it exists
                const checkResponse = await fetch(`/api/rooms/${roomId}`);
                
                if (checkResponse.ok) {
                    // Room exists and user has access, redirect to tracker
                    window.location.href = `/tracker/${roomId}`;
                } else if (checkResponse.status === 404) {
                    // Room doesn't exist
                    alert('Room not found. Please check the room ID and try again.');
                } else if (checkResponse.status === 403) {
                    // User doesn't have access, try to join
                    const joinResponse = await fetch(`/api/rooms/${roomId}/join`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (joinResponse.ok) {
                        // Successfully joined, redirect to tracker
                        window.location.href = `/tracker/${roomId}`;
                    } else {
                        const data = await joinResponse.json();
                        alert(data.message || 'Failed to join room. Please try again.');
                    }
                } else {
                    alert('Failed to join room. Please try again.');
                }
            } catch (error) {
                console.error('Join room error:', error);
                alert('An error occurred while joining the room. Please try again.');
            }
        });
    }
    
    // Add click handlers for enter room buttons
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('enter-room') || 
            (e.target.parentElement && e.target.parentElement.classList.contains('enter-room'))) {
            
            const button = e.target.classList.contains('enter-room') ? e.target : e.target.parentElement;
            const roomId = button.dataset.roomId;
            
            if (roomId) {
                window.location.href = `/tracker/${roomId}`;
            }
        }
    });
    
    // Initialize
    fetchRooms();
}); 