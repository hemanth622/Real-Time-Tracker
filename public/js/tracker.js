// Tracker page functionality
document.addEventListener('DOMContentLoaded', async () => {
    // Get room ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const pathParts = window.location.pathname.split('/');
    const roomId = pathParts[pathParts.length - 1];
    const isGuest = urlParams.get('guest') === 'true';
    
    if (!roomId) {
        alert('Room ID not found!');
        window.location.href = '/';
        return;
    }
    
    // Get user data
    let user;
    
    if (isGuest) {
        user = {
            id: 'guest_' + Date.now(),
            username: sessionStorage.getItem('guestName'),
            isGuest: true
        };
        
        if (!user.username) {
            window.location.href = `/?roomId=${roomId}`;
            return;
        }
        
        // Show guest badge in navbar
        document.querySelector('.navbar-brand').innerHTML += ' <span class="badge bg-warning text-dark">Guest Mode</span>';
        
        // Hide registered-only features
        document.querySelectorAll('.registered-only').forEach(el => {
            el.style.display = 'none';
        });
    } else {
        const token = localStorage.getItem('token');
        user = JSON.parse(localStorage.getItem('user') || '{}');
        
        if (!token || !user) {
            window.location.href = `/?roomId=${roomId}`;
            return;
        }
    }
    
    // Initialize socket connection
    const socket = io();
    
    // Initialize map
    const map = L.map('map').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: 'Real-Time Location Tracker',
        maxZoom: 19
    }).addTo(map);
    
    // Add map controls
    L.control.scale().addTo(map);
    
    // Store markers for each user
    const markers = {};
    const userColors = {};
    
    // Cache DOM elements
    const elements = {
        roomName: document.getElementById('room-name'),
        roomNameDisplay: document.getElementById('room-name-display'),
        roomDescription: document.getElementById('room-description'),
        locationAccuracy: document.getElementById('location-accuracy'),
        membersList: document.getElementById('members-list'),
        onlineCount: document.getElementById('online-count'),
        memberSearch: document.getElementById('member-search'),
        refreshLocationBtn: document.getElementById('refresh-location-btn'),
        shareRoomId: document.getElementById('share-room-id'),
        copyRoomId: document.getElementById('copy-room-id'),
        shareWhatsapp: document.getElementById('share-whatsapp'),
        shareEmail: document.getElementById('share-email'),
        leaveBtn: document.getElementById('leave-btn'),
        centerMapBtn: document.getElementById('center-map-btn'),
        chatMessages: document.getElementById('chat-messages'),
        chatForm: document.getElementById('chat-form'),
        chatInput: document.getElementById('chat-input')
    };
    
    try {
        // Initialize room info
        let roomName = 'Room: ' + roomId;
        let roomDescription = '';
        
        // Only fetch room details for registered users
        if (!isGuest) {
            try {
                const token = localStorage.getItem('token');
                const roomResponse = await fetch(`/api/rooms/${roomId}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                if (roomResponse.ok) {
                    const roomData = await roomResponse.json();
                    roomName = roomData.room.name;
                    roomDescription = roomData.room.description || '';
                }
            } catch (error) {
                console.warn('Could not fetch room details:', error);
            }
        }
        
        // Display room info
        elements.roomName.textContent = roomName;
        elements.roomNameDisplay.textContent = roomName;
        elements.roomDescription.textContent = roomDescription;
        
        // Join room
        socket.emit('join-room', { 
            userId: user.id,
            username: user.username, 
            roomId: roomId,
            isGuest: isGuest
        });

        // Add current user to members list immediately
        const currentUserListItem = createMemberListItem({
            id: user.id,
            username: user.username,
            isGuest: isGuest,
            isOwner: false // Will be updated when online-users event is received
        });
        elements.membersList.innerHTML = ''; // Clear any existing content
        elements.membersList.appendChild(currentUserListItem);
        elements.onlineCount.textContent = '1';
        
        // Function to create a member list item
        function createMemberListItem(member) {
            const color = getRandomColor(member.id);
            
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex align-items-center';
            li.dataset.userId = member.id;
            
            // Highlight current user
            if (member.id === user.id) {
                li.classList.add('active');
                li.style.backgroundColor = 'rgba(13, 110, 253, 0.1)';
            }
            
            const colorSpan = document.createElement('span');
            colorSpan.className = 'member-color';
            colorSpan.style.backgroundColor = color;
            li.appendChild(colorSpan);
            
            const nameSpan = document.createElement('span');
            nameSpan.textContent = member.username;
            
            // Add "You" indicator for current user
            if (member.id === user.id) {
                const youBadge = document.createElement('span');
                youBadge.className = 'badge bg-info ms-1';
                youBadge.textContent = 'You';
                nameSpan.appendChild(youBadge);
            }
            
            // Add badges for guest and owner status
            if (member.isGuest) {
                const guestBadge = document.createElement('span');
                guestBadge.className = 'badge bg-warning text-dark ms-1';
                guestBadge.textContent = 'Guest';
                nameSpan.appendChild(guestBadge);
            }
            
            if (member.isOwner) {
                const ownerBadge = document.createElement('span');
                ownerBadge.className = 'badge bg-primary ms-1';
                ownerBadge.textContent = 'Owner';
                nameSpan.appendChild(ownerBadge);
            }
            
            li.appendChild(nameSpan);
            
            // Add click handler to center map on user
            li.addEventListener('click', () => {
                if (markers[member.id]) {
                    map.setView(markers[member.id].getLatLng(), 16);
                    markers[member.id].openPopup();
                }
            });
            
            return li;
        }
        
        // Handle chat form submission
        elements.chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            const message = elements.chatInput.value.trim();
            if (!message) return;
            
            // Send message to server
            socket.emit('send-message', {
                userId: user.id,
                username: user.username,
                roomId: roomId,
                message: message,
                timestamp: new Date().toISOString(),
                isGuest: isGuest
            });
            
            // Clear input
            elements.chatInput.value = '';
        });
        
        // Receive chat messages
        socket.on('receive-message', (data) => {
            addChatMessage(data);
            
            // Show notification if chat modal is not open
            const chatModal = document.getElementById('chatModal');
            if (!chatModal.classList.contains('show')) {
                showNotification(`New message from ${data.username}`);
            }
        });
        
        // Receive chat history
        socket.on('chat-history', (messages) => {
            if (messages && messages.length > 0) {
                // Clear "no messages" placeholder
                elements.chatMessages.innerHTML = '';
                
                // Add each message
                messages.forEach(message => {
                    addChatMessage(message);
                });
                
                // Scroll to bottom
                elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
            }
        });
        
        // Function to add chat message to UI
        function addChatMessage(data) {
            // Clear "no messages" placeholder if present
            if (elements.chatMessages.querySelector('.text-center')) {
                elements.chatMessages.innerHTML = '';
            }
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `chat-message ${data.userId === user.id ? 'sent' : 'received'}`;
            
            // Only show username for received messages
            if (data.userId !== user.id) {
                const senderSpan = document.createElement('div');
                senderSpan.className = 'sender';
                senderSpan.textContent = data.username + (data.isGuest ? ' (Guest)' : '');
                messageDiv.appendChild(senderSpan);
            }
            
            const messageContent = document.createElement('div');
            messageContent.className = 'content';
            messageContent.textContent = data.message;
            messageDiv.appendChild(messageContent);
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'time';
            const messageTime = new Date(data.timestamp);
            timeSpan.textContent = messageTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            messageDiv.appendChild(timeSpan);
            
            elements.chatMessages.appendChild(messageDiv);
            
            // Scroll to bottom
            elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
        }
        
        // Function to show notification
        function showNotification(message) {
            if (!("Notification" in window)) return;
            
            if (Notification.permission === "granted") {
                new Notification("Location Tracker", { body: message });
            } else if (Notification.permission !== "denied") {
                Notification.requestPermission().then(permission => {
                    if (permission === "granted") {
                        new Notification("Location Tracker", { body: message });
                    }
                });
            }
        }
        
        // Generate random color for user
        function getRandomColor(userId) {
            if (userColors[userId]) {
                return userColors[userId];
            }
            
            const letters = '0123456789ABCDEF';
            let color = '#';
            for (let i = 0; i < 6; i++) {
                color += letters[Math.floor(Math.random() * 16)];
            }
            userColors[userId] = color;
            return color;
        }
        
        // Create custom marker icon
        function createCustomIcon(color, username, isGuest) {
            // Create a custom icon with user's initial and color
            const initial = username.charAt(0).toUpperCase();
            
            return L.divIcon({
                className: 'custom-marker',
                html: `
                    <div style="background-color: ${color}; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; font-weight: bold; box-shadow: 0 0 5px rgba(0,0,0,0.5);">
                        ${initial}
                    </div>
                    <div style="background-color: ${color}; width: 10px; height: 10px; transform: rotate(45deg); position: absolute; bottom: -5px; left: 10px; box-shadow: 0 0 5px rgba(0,0,0,0.5);"></div>
                    <div style="position: absolute; bottom: -20px; left: 50%; transform: translateX(-50%); white-space: nowrap; background-color: rgba(0,0,0,0.6); color: white; padding: 2px 5px; border-radius: 3px; font-size: 12px;">
                        ${username}${isGuest ? ' (G)' : ''}
                    </div>
                `,
                iconSize: [30, 42],
                iconAnchor: [15, 42]
            });
        }
        
        // Get high accuracy location
        let locationAttempts = 0;
        const maxLocationAttempts = 10; // Increase max attempts
        let locationWatchId;
        let bestPosition = null;
        
        function getHighAccuracyLocation() {
            // Update status
            elements.locationAccuracy.textContent = `Getting precise location (attempt ${locationAttempts + 1}/${maxLocationAttempts})...`;
            
            // Clear previous watch if any
            if (locationWatchId) {
                navigator.geolocation.clearWatch(locationWatchId);
            }
            
            // First try to get a single high-accuracy position
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    // Only use this position if it's better than what we have
                    if (!bestPosition || position.coords.accuracy < bestPosition.coords.accuracy) {
                        bestPosition = position;
                        handlePosition(position);
                    }
                    
                    // Then start watching with high accuracy options
                    locationWatchId = navigator.geolocation.watchPosition(
                        (watchPosition) => {
                            // Only update if this position is more accurate
                            if (!bestPosition || watchPosition.coords.accuracy < bestPosition.coords.accuracy) {
                                bestPosition = watchPosition;
                                handlePosition(watchPosition);
                            }
                        },
                        handlePositionError,
                        {
                            enableHighAccuracy: true,
                            timeout: 15000,
                            maximumAge: 0
                        }
                    );
                },
                handlePositionError,
                {
                    enableHighAccuracy: true,
                    timeout: 15000,
                    maximumAge: 0
                }
            );
        }
        
        function handlePosition(position) {
            const { latitude, longitude, accuracy } = position.coords;
            
            // Update accuracy display
            elements.locationAccuracy.textContent = `Location accuracy: ${Math.round(accuracy)} meters`;
            if (accuracy <= 100) {
                elements.locationAccuracy.className = 'badge bg-success';
            } else if (accuracy <= 500) {
                elements.locationAccuracy.className = 'badge bg-warning text-dark';
            } else {
                elements.locationAccuracy.className = 'badge bg-danger';
            }
            
            // Send location to server with room info
            socket.emit('send-location', { 
                userId: user.id,
                username: user.username,
                roomId: roomId,
                latitude, 
                longitude,
                accuracy,
                isGuest: isGuest
            });
            
            // If accuracy is good enough, stop trying to improve
            if (accuracy < 50) {
                locationAttempts = maxLocationAttempts;
            }
            
            // Try again if accuracy is poor and we haven't reached max attempts
            locationAttempts++;
            if (locationAttempts < maxLocationAttempts && accuracy > 100) {
                setTimeout(getHighAccuracyLocation, 3000);
            }
        }
        
        function handlePositionError(error) {
            console.error('Error getting location:', error);
            elements.locationAccuracy.textContent = 'Error: ' + getLocationErrorMessage(error);
            elements.locationAccuracy.className = 'badge bg-danger';
            
            // Try again if we haven't reached max attempts
            locationAttempts++;
            if (locationAttempts < maxLocationAttempts) {
                setTimeout(getHighAccuracyLocation, 2000);
            }
        }
        
        // Helper function to get readable error messages
        function getLocationErrorMessage(error) {
            switch(error.code) {
                case error.PERMISSION_DENIED:
                    return "Location permission denied";
                case error.POSITION_UNAVAILABLE:
                    return "Location unavailable";
                case error.TIMEOUT:
                    return "Location request timed out";
                default:
                    return "Unknown error";
            }
        }
        
        // Start getting location
        if (navigator.geolocation) {
            getHighAccuracyLocation();
        } else {
            alert('Geolocation is not supported by your browser. Please use a modern browser with location services.');
        }
        
        // Refresh location button
        elements.refreshLocationBtn.addEventListener('click', () => {
            // Reset location tracking
            locationAttempts = 0;
            bestPosition = null;
            
            // Clear existing location watch
            if (locationWatchId) {
                navigator.geolocation.clearWatch(locationWatchId);
                locationWatchId = null;
            }
            
            // Force the browser to get a fresh location
            if ('permissions' in navigator) {
                navigator.permissions.query({ name: 'geolocation' }).then(result => {
                    if (result.state === 'granted') {
                        // Clear cached positions by requesting with maximumAge: 0
                        navigator.geolocation.getCurrentPosition(
                            position => {
                                console.log('Cleared cached position');
                                // Start fresh location tracking
                                getHighAccuracyLocation();
                            },
                            error => {
                                console.error('Error clearing cache:', error);
                                // Start fresh location tracking anyway
                                getHighAccuracyLocation();
                            },
                            { maximumAge: 0, timeout: 10000, enableHighAccuracy: true }
                        );
                    } else {
                        // Start fresh location tracking
                        getHighAccuracyLocation();
                    }
                });
            } else {
                // Start fresh location tracking
                getHighAccuracyLocation();
            }
        });
        
        // Receive location updates for other users
        socket.on('receive-location', (data) => {
            const { userId, username, latitude, longitude, accuracy, isGuest } = data;
            
            // Update map view if this is our own location
            if (userId === user.id) {
                if (accuracy) {
                    elements.locationAccuracy.textContent = `Location accuracy: ${Math.round(accuracy)} meters`;
                    if (accuracy <= 100) {
                        elements.locationAccuracy.className = 'badge bg-success';
                    } else if (accuracy <= 500) {
                        elements.locationAccuracy.className = 'badge bg-warning text-dark';
                    } else {
                        elements.locationAccuracy.className = 'badge bg-danger';
                    }
                }
                
                // Set map view to our location with appropriate zoom level based on accuracy
                let zoomLevel = 16;
                if (accuracy > 5000) zoomLevel = 10;
                else if (accuracy > 1000) zoomLevel = 12;
                else if (accuracy > 500) zoomLevel = 14;
                
                map.setView([latitude, longitude], zoomLevel);
            }
            
            // Get or generate color for user
            const color = getRandomColor(userId);
            
            // Create or update marker
            if (markers[userId]) {
                markers[userId].setLatLng([latitude, longitude]);
            } else {
                const icon = createCustomIcon(color, username, isGuest);
                markers[userId] = L.marker([latitude, longitude], { icon }).addTo(map);
                
                // Add popup with user info
                markers[userId].bindPopup(`<b>${username}</b>${isGuest ? ' (Guest)' : ''}<br>Last updated: <span class="last-update">just now</span>`);
                
                // Update last update time every minute
                setInterval(() => {
                    const popup = markers[userId].getPopup();
                    if (popup) {
                        const lastUpdate = new Date(markers[userId].lastUpdate || Date.now());
                        const minutes = Math.floor((Date.now() - lastUpdate) / 60000);
                        const timeText = minutes < 1 ? 'just now' : `${minutes} min ago`;
                        
                        const content = popup.getContent().replace(/<span class="last-update">.*?<\/span>/, `<span class="last-update">${timeText}</span>`);
                        popup.setContent(content);
                        
                        if (popup.isOpen()) {
                            popup.update();
                        }
                    }
                }, 60000);
            }
            
            // Store last update time
            markers[userId].lastUpdate = Date.now();
        });
        
        // Handle user disconnection
        socket.on('user-disconnected', (userId) => {
            if (markers[userId]) {
                map.removeLayer(markers[userId]);
                delete markers[userId];
            }
        });
        
        // Receive online users list
        socket.on('online-users', (users) => {
            console.log('Received online users:', users);
            
            // Update members list
            elements.membersList.innerHTML = '';
            elements.onlineCount.textContent = users.length;
            
            // Check if current user is in the list
            const currentUserInList = users.some(member => member.id === user.id);
            
            // If current user is not in the list, add them
            if (!currentUserInList) {
                users.push({
                    id: user.id,
                    username: user.username,
                    isGuest: isGuest,
                    isOwner: false
                });
                console.log('Added current user to list as they were missing');
            }
            
            // Add all users to the list
            users.forEach(member => {
                const listItem = createMemberListItem(member);
                elements.membersList.appendChild(listItem);
            });
        });
        
        // Member search
        elements.memberSearch.addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const members = elements.membersList.querySelectorAll('li');
            
            members.forEach(member => {
                const username = member.textContent.toLowerCase();
                if (username.includes(searchTerm)) {
                    member.style.display = '';
                } else {
                    member.style.display = 'none';
                }
            });
        });
        
        // Center map button
        if (elements.centerMapBtn) {
            elements.centerMapBtn.addEventListener('click', () => {
                // Find user's marker
                const userMarker = markers[user.id];
                if (userMarker) {
                    // Center map on user's location
                    map.setView(userMarker.getLatLng(), map.getZoom());
                    // Open popup
                    userMarker.openPopup();
                } else {
                    alert('Your location is not yet available. Please wait or refresh your location.');
                }
            });
        }
        
        // Share room functionality
        elements.shareRoomId.value = roomId;
        
        elements.copyRoomId.addEventListener("click", () => {
            elements.shareRoomId.select();
            document.execCommand("copy");
            
            // Show success message
            const originalText = elements.copyRoomId.innerHTML;
            elements.copyRoomId.innerHTML = '<i class="bi bi-check-lg me-1"></i>Copied!';
            setTimeout(() => {
                elements.copyRoomId.innerHTML = originalText;
            }, 2000);
        });
        
        // WhatsApp share
        elements.shareWhatsapp.addEventListener("click", () => {
            const text = `Join my location tracking room! Room ID: ${roomId}`;
            const url = `https://wa.me/?text=${encodeURIComponent(text)}`;
            window.open(url, "_blank");
        });
        
        // Email share
        elements.shareEmail.addEventListener("click", () => {
            const subject = "Join my location tracking room";
            const body = `Join my location tracking room!\n\nRoom ID: ${roomId}\n\nJust go to the app and enter this Room ID to join.`;
            const url = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
            window.location.href = url;
        });
        
        // Leave button
        elements.leaveBtn.addEventListener("click", () => {
            if (confirm("Are you sure you want to leave this room?")) {
                window.location.href = isGuest ? "/" : "/dashboard";
            }
        });
        
    } catch (error) {
        console.error("Error in tracker:", error);
        alert("An error occurred. Returning to home page.");
        window.location.href = "/";
    }
}); 