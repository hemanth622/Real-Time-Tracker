// Import required modules
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const helmet = require('helmet');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000; // Use standard port 3000 as fallback
const HOST = '0.0.0.0';  // Listen on all interfaces

// Enhance security with helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://cdn.socket.io"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://*.tile.openstreetmap.org"],
            connectSrc: ["'self'", "wss:", "https://*.tile.openstreetmap.org"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net"],
        }
    }
}));

// Enable compression for all responses
app.use(compression());

// Set view engine
app.set('view engine', 'ejs');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Memory-based storage (in production, use a database)
const users = [];
const rooms = [];
const activeUsers = new Map(); // userId -> socketId
const userRooms = new Map(); // userId -> Set of roomIds
const roomUsers = new Map(); // roomId -> Set of userIds
const roomMessages = new Map(); // roomId -> array of messages

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ message: 'Authentication required' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// Routes
// Home route
app.get('/', (req, res) => {
    res.render('index');
});

// Dashboard route (requires authentication)
app.get('/dashboard', (req, res) => {
    res.render('dashboard');
});

// Tracker route
app.get('/tracker/:roomId', (req, res) => {
    const roomId = req.params.roomId;
    // Check if room exists
    const room = rooms.find(r => r.id === roomId);
    
    if (!room) {
        return res.status(404).render('error', { message: 'Room not found' });
    }
    
    res.render('tracker');
});

// API Routes
// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        
        // Validate input
        if (!email || !username || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        
        // Check if user already exists
        if (users.some(user => user.email === email)) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new user
        const newUser = {
            id: uuidv4(),
            email,
            username,
            password: hashedPassword,
            createdAt: new Date()
        };
        
        // Save user
        users.push(newUser);
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        
        // Create JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Return user info (excluding password) and token
        const userResponse = {
            id: user.id,
            email: user.email,
            username: user.username
        };
        
        res.json({ user: userResponse, token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Create room endpoint
app.post('/api/rooms/create', authenticateToken, (req, res) => {
    try {
        const { name, description } = req.body;
        const userId = req.user.id;
        
        if (!name) {
            return res.status(400).json({ message: 'Room name is required' });
        }
        
        // Generate unique room ID (6 characters)
        const generateRoomId = () => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let result = '';
            for (let i = 0; i < 6; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        };
        
        // Ensure room ID is unique
        let roomId;
        do {
            roomId = generateRoomId();
        } while (rooms.some(r => r.id === roomId));
        
        // Create new room
        const newRoom = {
            id: roomId,
            name,
            description: description || '',
            ownerId: userId,
            createdAt: new Date(),
            members: [userId]
        };
        
        // Save room
        rooms.push(newRoom);
        
        // Add room to user's rooms
        if (!userRooms.has(userId)) {
            userRooms.set(userId, new Set());
        }
        userRooms.get(userId).add(roomId);
        
        // Initialize room users
        roomUsers.set(roomId, new Set([userId]));
        
        // Initialize room messages
        roomMessages.set(roomId, []);
        
        res.status(201).json({ 
            message: 'Room created successfully',
            room: {
                id: newRoom.id,
                name: newRoom.name,
                description: newRoom.description,
                createdAt: newRoom.createdAt
            }
        });
    } catch (error) {
        console.error('Create room error:', error);
        res.status(500).json({ message: 'Server error during room creation' });
    }
});

// Get rooms endpoint
app.get('/api/rooms', authenticateToken, (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get rooms owned by user
        const myRooms = rooms.filter(room => room.ownerId === userId).map(room => ({
            id: room.id,
            name: room.name,
            description: room.description,
            createdAt: room.createdAt,
            memberCount: room.members.length
        }));
        
        // Get rooms joined by user (excluding owned rooms)
        const joinedRooms = rooms.filter(room => 
            room.ownerId !== userId && room.members.includes(userId)
        ).map(room => {
            const owner = users.find(u => u.id === room.ownerId);
            return {
                id: room.id,
                name: room.name,
                description: room.description,
                createdAt: room.createdAt,
                owner: owner ? owner.username : 'Unknown',
                memberCount: room.members.length
            };
        });
        
        res.json({ myRooms, joinedRooms });
    } catch (error) {
        console.error('Get rooms error:', error);
        res.status(500).json({ message: 'Server error while fetching rooms' });
    }
});

// Get room details
app.get('/api/rooms/:roomId', authenticateToken, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        
        // Find room
        const room = rooms.find(r => r.id === roomId);
        
        if (!room) {
            return res.status(404).json({ message: 'Room not found' });
        }
        
        // Check if user is member of the room
        if (!room.members.includes(userId)) {
            return res.status(403).json({ message: 'You are not a member of this room' });
        }
        
        // Get owner info
        const owner = users.find(u => u.id === room.ownerId);
        
        // Get members info
        const members = room.members.map(memberId => {
            const member = users.find(u => u.id === memberId);
            return member ? {
                id: member.id,
                username: member.username,
                isOwner: member.id === room.ownerId
            } : null;
        }).filter(Boolean);
        
        res.json({
            room: {
                id: room.id,
                name: room.name,
                description: room.description,
                createdAt: room.createdAt,
                owner: owner ? {
                    id: owner.id,
                    username: owner.username
                } : null,
                members,
                isOwner: room.ownerId === userId
            }
        });
    } catch (error) {
        console.error('Get room details error:', error);
        res.status(500).json({ message: 'Server error while fetching room details' });
    }
});

// Delete room endpoint
app.delete('/api/rooms/:roomId', authenticateToken, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        
        // Find room
        const roomIndex = rooms.findIndex(r => r.id === roomId);
        
        if (roomIndex === -1) {
            return res.status(404).json({ message: 'Room not found' });
        }
        
        // Check if user is owner
        if (rooms[roomIndex].ownerId !== userId) {
            return res.status(403).json({ message: 'Only the room owner can delete the room' });
        }
        
        // Remove room from all users' rooms
        rooms[roomIndex].members.forEach(memberId => {
            if (userRooms.has(memberId)) {
                userRooms.get(memberId).delete(roomId);
            }
        });
        
        // Remove room from roomUsers and roomMessages
        roomUsers.delete(roomId);
        roomMessages.delete(roomId);
        
        // Remove room
        rooms.splice(roomIndex, 1);
        
        res.json({ message: 'Room deleted successfully' });
    } catch (error) {
        console.error('Delete room error:', error);
        res.status(500).json({ message: 'Server error while deleting room' });
    }
});

// Leave room endpoint
app.post('/api/rooms/:roomId/leave', authenticateToken, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        
        // Find room
        const room = rooms.find(r => r.id === roomId);
        
        if (!room) {
            return res.status(404).json({ message: 'Room not found' });
        }
        
        // Check if user is member
        if (!room.members.includes(userId)) {
            return res.status(400).json({ message: 'You are not a member of this room' });
        }
        
        // Check if user is owner
        if (room.ownerId === userId) {
            return res.status(400).json({ message: 'Room owner cannot leave. Please delete the room instead.' });
        }
        
        // Remove user from room members
        room.members = room.members.filter(id => id !== userId);
        
        // Remove room from user's rooms
        if (userRooms.has(userId)) {
            userRooms.get(userId).delete(roomId);
        }
        
        // Remove user from roomUsers
        if (roomUsers.has(roomId)) {
            roomUsers.get(roomId).delete(userId);
        }
        
        res.json({ message: 'Left room successfully' });
    } catch (error) {
        console.error('Leave room error:', error);
        res.status(500).json({ message: 'Server error while leaving room' });
    }
});

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.io
const io = socketIo(server);

// Socket.io connection handler
io.on('connection', (socket) => {
    console.log('New client connected');
    
    // Join room
    socket.on('join-room', (data) => {
        const { userId, username, roomId, isGuest } = data;
        
        console.log(`User ${username} (${isGuest ? 'Guest' : 'Registered'}) joined room ${roomId}`);
        
        // Add user to socket room
        socket.join(roomId);
        
        // Store user connection info
        if (!isGuest) {
            activeUsers.set(userId, socket.id);
        }
        
        // Add room to user's rooms
        if (!isGuest && !userRooms.has(userId)) {
            userRooms.set(userId, new Set());
            userRooms.get(userId).add(roomId);
        }
        
        // Add user to room users
        if (!roomUsers.has(roomId)) {
            roomUsers.set(roomId, new Set());
        }
        roomUsers.get(roomId).add(userId);
        
        // Find room
        let room = rooms.find(r => r.id === roomId);
        
        // If room doesn't exist (possible for guest access), create it
        if (!room && isGuest) {
            room = {
                id: roomId,
                name: `Guest Room ${roomId}`,
                description: 'Created by guest access',
                ownerId: null,
                createdAt: new Date(),
                members: []
            };
            rooms.push(room);
            roomMessages.set(roomId, []);
        }
        
        // If user is not a guest and not already in room members, add them
        if (!isGuest && room && !room.members.includes(userId)) {
            room.members.push(userId);
        }
        
        // Always add the current user first to ensure they're included
        const onlineUsers = [{
            id: userId,
            username: username,
            isGuest: isGuest,
            isOwner: room && room.ownerId === userId
        }];
        
        // Add all registered users from this room (except the current user who was already added)
        if (room && room.members) {
            for (const memberId of room.members) {
                // Skip the current user as they were already added
                if (memberId === userId && !isGuest) continue;
                
                const member = users.find(u => u.id === memberId);
                if (member) {
                    onlineUsers.push({
                        id: memberId,
                        username: member.username,
                        isGuest: false,
                        isOwner: room.ownerId === memberId
                    });
                }
            }
        }
        
        // Ensure the room owner is included in the list
        if (room && room.ownerId && room.ownerId !== userId) {
            const ownerExists = onlineUsers.some(u => u.id === room.ownerId);
            if (!ownerExists) {
                const owner = users.find(u => u.id === room.ownerId);
                if (owner) {
                    onlineUsers.push({
                        id: room.ownerId,
                        username: owner.username,
                        isGuest: false,
                        isOwner: true
                    });
                }
            }
        }
        
        // Emit the online users list to all clients in the room
        io.to(roomId).emit('online-users', onlineUsers);
        
        // Send chat history to new user
        if (roomMessages.has(roomId)) {
            socket.emit('chat-history', roomMessages.get(roomId));
        }
        
        // Notify room that user joined
        socket.to(roomId).emit('user-joined', {
            userId,
            username,
            isGuest
        });
    });
    
    // Send location
    socket.on('send-location', (data) => {
        const { userId, username, roomId, latitude, longitude, accuracy, isGuest } = data;
        
        // Broadcast location to all users in the room
        io.to(roomId).emit('receive-location', {
            userId,
            username,
            latitude,
            longitude,
            accuracy,
            isGuest
        });
    });
    
    // Send message
    socket.on('send-message', (data) => {
        const { userId, username, roomId, message, timestamp, isGuest } = data;
        
        // Create message object
        const messageObj = {
            userId,
            username,
            message,
            timestamp,
            isGuest
        };
        
        // Store message in room messages
        if (roomMessages.has(roomId)) {
            // Limit message history to 100 messages per room
            const messages = roomMessages.get(roomId);
            messages.push(messageObj);
            
            if (messages.length > 100) {
                messages.shift();
            }
        }
        
        // Broadcast message to all users in the room
        io.to(roomId).emit('receive-message', messageObj);
    });
    
    // Disconnect handler
    socket.on('disconnect', () => {
        console.log('Client disconnected');
        
        // Find user by socket ID
        let disconnectedUserId = null;
        for (const [userId, socketId] of activeUsers.entries()) {
            if (socketId === socket.id) {
                disconnectedUserId = userId;
                break;
            }
        }
        
        if (disconnectedUserId) {
            // Remove user from active users
            activeUsers.delete(disconnectedUserId);
            
            // Notify all rooms the user was in
            if (userRooms.has(disconnectedUserId)) {
                for (const roomId of userRooms.get(disconnectedUserId)) {
                    // Remove user from room users
                    if (roomUsers.has(roomId)) {
                        roomUsers.get(roomId).delete(disconnectedUserId);
                        
                        // Find the room for owner check
                        const room = rooms.find(r => r.id === roomId);
                        
                        // Send updated user list
                        const roomUsersList = Array.from(roomUsers.get(roomId)).map(id => {
                            const user = users.find(u => u.id === id);
                            return user ? {
                                id,
                                username: user.username,
                                isGuest: false,
                                isOwner: room && room.ownerId === id
                            } : null;
                        }).filter(Boolean);
                        
                        io.to(roomId).emit('online-users', roomUsersList);
                        
                        // Notify room that user disconnected
                        io.to(roomId).emit('user-disconnected', disconnectedUserId);
                    }
                }
            }
        }
    });
});

// Start server with error handling
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const newPort = parseInt(PORT) + 1;
        console.error(`Port ${PORT} is already in use. Trying port ${newPort}...`);
        server.listen(newPort, () => {
            console.log(`Server running on port ${newPort}`);
        });
    } else {
        console.error('Server error:', err);
    }
});
