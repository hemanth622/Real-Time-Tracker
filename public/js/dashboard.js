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
        roomName: document.getElementById('room-name'),
        roomDescription: document.getElementById('room-description'),
        myRooms: document.getElementById('my-rooms'),
        joinedRooms: document.getElementById('joined-rooms'),
        myRoomsCount: document.getElementById('my-rooms-count'),
        joinedRoomsCount: document.getElementById('joined-rooms-count'),
        noRoomsMessage: document.getElementById('no-rooms-message'),
        noJoinedRoomsMessage: document.getElementById('no-joined-rooms-message')
    };

    // Check if user is logged in
    const token = localStorage.getItem('token');
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    if (!token || !user) {
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
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/';
    }
    
    // Add logout handler
    if (elements.logoutBtn) {
        elements.logoutBtn.onclick = handleLogout;
    }
    
    // Fetch rooms
    async function fetchRooms() {
        try {
            const response = await fetch('/api/rooms', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
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
        console.log('Created enter button with roomId:', room.id);
        
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
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
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
    
    // Initialize
    fetchRooms();
}); 