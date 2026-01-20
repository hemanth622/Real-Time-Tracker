// Import required modules
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { z } = require('zod');
const sanitizeHtml = require('sanitize-html');
const { connectMongo, isMongoConfigured, isMongoConnected } = require('./db');
const User = require('./models/User');
const Room = require('./models/Room');
const LocationPing = require('./models/LocationPing');

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
app.use(cookieParser());

// --- CSRF protection (double-submit cookie) ---
// We keep JWT in an HttpOnly cookie, so we require a second, JS-readable token (csrfToken)
// to be echoed back in a header for all state-changing /api requests.
const CSRF_COOKIE = 'csrfToken';
const CSRF_HEADER = 'x-csrf-token';

function issueCsrfToken(res) {
    const token = crypto.randomBytes(32).toString('base64url');
    res.cookie(CSRF_COOKIE, token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 12 * 60 * 60 * 1000, // 12 hours
    });
    return token;
}

function sameOrigin(req) {
    const origin = req.headers.origin;
    const host = req.headers.host;
    if (!origin || !host) return true; // allow non-browser clients (curl)
    try {
        const u = new URL(origin);
        return u.host === host;
    } catch {
        return false;
    }
}

app.get('/api/csrf-token', (req, res) => {
    const existing = req.cookies && req.cookies[CSRF_COOKIE];
    const token = existing || issueCsrfToken(res);
    res.json({ csrfToken: token });
});

app.use('/api', (req, res, next) => {
    // Enforce origin checks for browsers
    if (!sameOrigin(req)) return res.status(403).json({ message: 'Bad origin' });

    // Enforce CSRF for state-changing endpoints
    const method = req.method.toUpperCase();
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return next();
    if (req.path === '/csrf-token') return next();

    const cookieToken = req.cookies && req.cookies[CSRF_COOKIE];
    const headerToken = req.headers[CSRF_HEADER];
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        return res.status(403).json({ message: 'CSRF token missing or invalid' });
    }

    next();
});

// Memory-based storage (in production, use a database)
const users = [];
const rooms = [];
const activeUsers = new Map(); // userId -> socketId
const userRooms = new Map(); // userId -> Set of roomIds
const roomUsers = new Map(); // roomId -> Set of userIds
const roomMessages = new Map(); // roomId -> array of messages
const roomSettings = new Map(); // roomId -> settings snapshot for socket enforcement

// --- Validation helpers ---
const validateBody = (schema) => (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({
            message: 'Invalid request',
            errors: parsed.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }))
        });
    }
    req.body = parsed.data;
    next();
};

const schemas = {
    register: z.object({
        email: z.string().email().max(254),
        username: z.string().min(2).max(40),
        password: z.string().min(8).max(128)
    }),
    login: z.object({
        email: z.string().email().max(254),
        password: z.string().min(1).max(128)
    }),
    createRoom: z.object({
        name: z.string().min(2).max(60),
        description: z.string().max(240).optional().default('')
    }),
    toggle: z.object({
        enabled: z.boolean().optional(),
        muted: z.boolean().optional(),
        disabled: z.boolean().optional(),
    }),
    adminUserId: z.object({
        userId: z.string().min(1).max(128)
    }),
};

// JWT Secret (required in production)
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET is not set. Using an unsafe default secret for development only.');
}
const RESOLVED_JWT_SECRET = JWT_SECRET || 'development-insecure-secret';

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];

    // Fallback to HttpOnly cookie if no Authorization header
    if (!token && req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }
    
    if (!token) return res.status(401).json({ message: 'Authentication required' });
    
    jwt.verify(token, RESOLVED_JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// Basic rate limiting (helps against brute-force and abuse)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 requests per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});

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
app.get('/tracker/:roomId', async (req, res) => {
    const roomId = req.params.roomId;

    // Check if room exists
    let room = rooms.find(r => r.id === roomId);
    if (!room && isMongoConnected()) {
        const roomDoc = await Room.findOne({ roomId }).lean();
        if (roomDoc) {
            room = {
                id: roomDoc.roomId,
                name: roomDoc.name,
                description: roomDoc.description || '',
                ownerId: roomDoc.ownerId ? roomDoc.ownerId.toString() : null,
                createdAt: roomDoc.createdAt || new Date(),
                members: (roomDoc.members || []).map(m => m.toString())
            };
            rooms.push(room);
        }
    }
    
    if (!room) {
        return res.status(404).render('error', { message: 'Room not found' });
    }
    
    res.render('tracker');
});

// API Routes
// Register endpoint
app.post('/api/auth/register', authLimiter, validateBody(schemas.register), async (req, res) => {
    try {
        const { email, username, password } = req.body;
        
        // Validate input
        if (!email || !username || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        
        // Check if user already exists
        if (isMongoConnected()) {
            const existing = await User.findOne({ email: String(email).toLowerCase() }).lean();
            if (existing) {
                return res.status(400).json({ message: 'User already exists with this email' });
            }
        } else {
            if (users.some(user => user.email === email)) {
                return res.status(400).json({ message: 'User already exists with this email' });
            }
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new user
        let newUser;
        if (isMongoConnected()) {
            const userDoc = await User.create({
                email,
                username,
                passwordHash: hashedPassword
            });
            newUser = {
                id: userDoc._id.toString(),
                email: userDoc.email,
                username: userDoc.username,
                password: userDoc.passwordHash,
                createdAt: userDoc.createdAt || new Date()
            };
        } else {
            newUser = {
                id: uuidv4(),
                email,
                username,
                password: hashedPassword,
                createdAt: new Date()
            };
        }

        // Save user in memory cache (used by socket layer and some endpoints)
        users.push(newUser);
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// Logout endpoint (clears auth cookie)
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
    });
    res.json({ message: 'Logged out' });
});

// Login endpoint
app.post('/api/auth/login', authLimiter, validateBody(schemas.login), async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        let user = users.find(u => u.email === email);
        if (!user && isMongoConnected()) {
            const userDoc = await User.findOne({ email: String(email).toLowerCase() }).lean();
            if (userDoc) {
                user = {
                    id: userDoc._id.toString(),
                    email: userDoc.email,
                    username: userDoc.username,
                    password: userDoc.passwordHash
                };
                users.push(user);
            }
        }
        
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
            RESOLVED_JWT_SECRET,
            { expiresIn: '12h' }
        );

        // Set HttpOnly cookie for auth
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 12 * 60 * 60 * 1000, // 12 hours
        });
        
        // Return user info (excluding password) and token (for backward compatibility)
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
app.post('/api/rooms/create', authenticateToken, apiLimiter, validateBody(schemas.createRoom), (req, res) => {
    try {
        const { name, description } = req.body;
        const userId = req.user.id;
        
        if (!name) {
            return res.status(400).json({ message: 'Room name is required' });
        }
        
        // Generate unique room ID (6 digits)
        const generateRoomId = () => {
            const digits = '0123456789';
            let result = '';
            for (let i = 0; i < 6; i++) {
                result += digits.charAt(Math.floor(Math.random() * digits.length));
            }
            return result;
        };
        
        // Ensure room ID is unique
        let roomId;
        do {
            roomId = generateRoomId();
        } while (rooms.some(r => r.id === roomId));
        
        // Create new room
        const inviteToken = crypto.randomBytes(18).toString('base64url');
        const newRoom = {
            id: roomId,
            name,
            description: description || '',
            ownerId: userId,
            createdAt: new Date(),
            members: [userId],
            inviteToken,
            bannedUserIds: [],
            chatMuted: false,
            locationRequestsDisabled: false,
            locationHistoryEnabled: false,
        };
        
        // Save room
        rooms.push(newRoom);
        roomSettings.set(roomId, {
            inviteToken,
            bannedUserIds: [],
            chatMuted: false,
            locationRequestsDisabled: false,
            locationHistoryEnabled: false,
        });
        if (isMongoConnected()) {
            // Best-effort persistence; keep API responsive even if Mongo blips.
            Room.create({
                roomId: newRoom.id,
                name: newRoom.name,
                description: newRoom.description,
                ownerId: userId,
                members: [userId],
                inviteToken,
                bannedUserIds: [],
                chatMuted: false,
                locationRequestsDisabled: false,
                locationHistoryEnabled: false,
            }).catch(err => console.error('Mongo room create error:', err));
        }
        
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
app.get('/api/rooms', authenticateToken, apiLimiter, (req, res) => {
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
app.get('/api/rooms/:roomId', authenticateToken, apiLimiter, (req, res) => {
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

// Join room endpoint (registered users)
app.post('/api/rooms/:roomId/join', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;

        const room = rooms.find(r => r.id === roomId);
        if (!room) return res.status(404).json({ message: 'Room not found' });

        const settings = roomSettings.get(roomId) || {};
        if (settings.bannedUserIds && settings.bannedUserIds.includes(userId)) {
            return res.status(403).json({ message: 'You are banned from this room' });
        }

        if (!room.members.includes(userId)) {
            room.members.push(userId);
            if (isMongoConnected()) {
                Room.updateOne({ roomId }, { $addToSet: { members: userId } })
                    .catch(err => console.error('Mongo room join error:', err));
            }
        }

        if (!userRooms.has(userId)) userRooms.set(userId, new Set());
        userRooms.get(userId).add(roomId);

        res.json({ message: 'Joined room successfully' });
    } catch (error) {
        console.error('Join room error:', error);
        res.status(500).json({ message: 'Server error while joining room' });
    }
});

// Invite link (owner generates)
app.get('/api/rooms/:roomId/invite', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        const room = rooms.find(r => r.id === roomId);
        if (!room) return res.status(404).json({ message: 'Room not found' });
        if (room.ownerId !== userId) return res.status(403).json({ message: 'Only the room owner can create invite links' });

        let settings = roomSettings.get(roomId);
        if (!settings) {
            settings = { inviteToken: room.inviteToken || crypto.randomBytes(18).toString('base64url') };
            roomSettings.set(roomId, settings);
        }
        if (!settings.inviteToken) settings.inviteToken = crypto.randomBytes(18).toString('base64url');
        room.inviteToken = settings.inviteToken;

        if (isMongoConnected()) {
            Room.updateOne({ roomId }, { $set: { inviteToken: settings.inviteToken } })
                .catch(err => console.error('Mongo invite token update error:', err));
        }

        res.json({ inviteUrl: `/invite/${settings.inviteToken}` });
    } catch (error) {
        console.error('Invite link error:', error);
        res.status(500).json({ message: 'Server error while creating invite link' });
    }
});

// Invite accept route
app.get('/invite/:token', async (req, res) => {
    const token = req.params.token;
    try {
        // Find room in memory first
        let room = rooms.find(r => r.inviteToken === token) || null;
        if (!room && isMongoConnected()) {
            const roomDoc = await Room.findOne({ inviteToken: token }).lean();
            if (roomDoc) {
                room = {
                    id: roomDoc.roomId,
                    name: roomDoc.name,
                    description: roomDoc.description || '',
                    ownerId: roomDoc.ownerId ? roomDoc.ownerId.toString() : null,
                    createdAt: roomDoc.createdAt || new Date(),
                    members: (roomDoc.members || []).map(m => m.toString()),
                    inviteToken: roomDoc.inviteToken,
                    bannedUserIds: (roomDoc.bannedUserIds || []).map(x => x.toString()),
                    chatMuted: !!roomDoc.chatMuted,
                    locationRequestsDisabled: !!roomDoc.locationRequestsDisabled,
                    locationHistoryEnabled: !!roomDoc.locationHistoryEnabled,
                };
                rooms.push(room);
                roomSettings.set(room.id, {
                    inviteToken: room.inviteToken,
                    bannedUserIds: room.bannedUserIds || [],
                    chatMuted: !!room.chatMuted,
                    locationRequestsDisabled: !!room.locationRequestsDisabled,
                    locationHistoryEnabled: !!room.locationHistoryEnabled,
                });
            }
        }

        if (!room) return res.status(404).render('error', { message: 'Invite link not found' });

        // If logged in, add to room and redirect to tracker
        const tokenCookie = req.cookies && req.cookies.token;
        if (tokenCookie) {
            try {
                const user = jwt.verify(tokenCookie, RESOLVED_JWT_SECRET);
                const userId = user.id;
                const settings = roomSettings.get(room.id) || {};
                if (settings.bannedUserIds && settings.bannedUserIds.includes(userId)) {
                    return res.status(403).render('error', { message: 'You are banned from this room' });
                }
                if (!room.members.includes(userId)) {
                    room.members.push(userId);
                    if (isMongoConnected()) {
                        Room.updateOne({ roomId: room.id }, { $addToSet: { members: userId } })
                            .catch(err => console.error('Mongo invite join error:', err));
                    }
                }
                if (!userRooms.has(userId)) userRooms.set(userId, new Set());
                userRooms.get(userId).add(room.id);
                return res.redirect(`/tracker/${room.id}`);
            } catch {
                // fall through to login page redirect
            }
        }

        // Not logged in: send to home with roomId prefilled
        return res.redirect(`/?roomId=${room.id}`);
    } catch (err) {
        console.error('Invite accept error:', err);
        return res.status(500).render('error', { message: 'Server error while processing invite' });
    }
});

// Delete room endpoint
app.delete('/api/rooms/:roomId', authenticateToken, apiLimiter, (req, res) => {
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
        roomSettings.delete(roomId);
        
        // Remove room
        rooms.splice(roomIndex, 1);
        if (isMongoConnected()) {
            Room.deleteOne({ roomId }).catch(err => console.error('Mongo room delete error:', err));
        }
        
        res.json({ message: 'Room deleted successfully' });
    } catch (error) {
        console.error('Delete room error:', error);
        res.status(500).json({ message: 'Server error while deleting room' });
    }
});

// Leave room endpoint
app.post('/api/rooms/:roomId/leave', authenticateToken, apiLimiter, (req, res) => {
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
        if (isMongoConnected()) {
            Room.updateOne({ roomId }, { $pull: { members: userId } })
                .catch(err => console.error('Mongo room leave error:', err));
        }
        
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

// --- Admin controls (owner only) ---
const requireOwner = (req, res, next) => {
    const roomId = req.params.roomId;
    const room = rooms.find(r => r.id === roomId);
    if (!room) return res.status(404).json({ message: 'Room not found' });
    if (room.ownerId !== req.user.id) return res.status(403).json({ message: 'Only the room owner can perform this action' });
    req.room = room;
    next();
};

app.post('/api/rooms/:roomId/admin/mute-chat', authenticateToken, apiLimiter, requireOwner, validateBody(schemas.toggle), async (req, res) => {
    const roomId = req.params.roomId;
    const muted = Boolean(req.body.muted);
    const settings = roomSettings.get(roomId) || {};
    settings.chatMuted = muted;
    roomSettings.set(roomId, settings);
    req.room.chatMuted = muted;
    if (isMongoConnected()) {
        Room.updateOne({ roomId }, { $set: { chatMuted: muted } }).catch(err => console.error('Mongo mute-chat error:', err));
    }
    res.json({ message: 'Updated', chatMuted: muted });
});

app.post('/api/rooms/:roomId/admin/disable-location-requests', authenticateToken, apiLimiter, requireOwner, validateBody(schemas.toggle), async (req, res) => {
    const roomId = req.params.roomId;
    const disabled = Boolean(req.body.disabled);
    const settings = roomSettings.get(roomId) || {};
    settings.locationRequestsDisabled = disabled;
    roomSettings.set(roomId, settings);
    req.room.locationRequestsDisabled = disabled;
    if (isMongoConnected()) {
        Room.updateOne({ roomId }, { $set: { locationRequestsDisabled: disabled } }).catch(err => console.error('Mongo disable-location-requests error:', err));
    }
    res.json({ message: 'Updated', locationRequestsDisabled: disabled });
});

app.post('/api/rooms/:roomId/admin/location-history', authenticateToken, apiLimiter, requireOwner, validateBody(schemas.toggle), async (req, res) => {
    const roomId = req.params.roomId;
    const enabled = Boolean(req.body.enabled);
    const settings = roomSettings.get(roomId) || {};
    settings.locationHistoryEnabled = enabled;
    roomSettings.set(roomId, settings);
    req.room.locationHistoryEnabled = enabled;
    if (isMongoConnected()) {
        Room.updateOne({ roomId }, { $set: { locationHistoryEnabled: enabled } }).catch(err => console.error('Mongo location-history setting error:', err));
    }
    res.json({ message: 'Updated', locationHistoryEnabled: enabled });
});

app.post('/api/rooms/:roomId/admin/ban', authenticateToken, apiLimiter, requireOwner, validateBody(schemas.adminUserId), async (req, res) => {
    const roomId = req.params.roomId;
    const targetUserId = req.body.userId;
    const settings = roomSettings.get(roomId) || { bannedUserIds: [] };
    settings.bannedUserIds = settings.bannedUserIds || [];
    if (!settings.bannedUserIds.includes(targetUserId)) settings.bannedUserIds.push(targetUserId);
    roomSettings.set(roomId, settings);
    req.room.bannedUserIds = settings.bannedUserIds;

    // Also remove from members
    req.room.members = (req.room.members || []).filter(id => id !== targetUserId);
    if (userRooms.has(targetUserId)) userRooms.get(targetUserId).delete(roomId);

    if (isMongoConnected()) {
        Room.updateOne(
            { roomId },
            { $addToSet: { bannedUserIds: targetUserId }, $pull: { members: targetUserId } }
        ).catch(err => console.error('Mongo ban error:', err));
    }

    // Kick if currently connected
    const socketId = activeUsers.get(targetUserId);
    if (socketId) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
            s.emit('kicked', { roomId, reason: 'banned' });
            s.leave(roomId);
        }
    }

    res.json({ message: 'User banned' });
});

app.post('/api/rooms/:roomId/admin/kick', authenticateToken, apiLimiter, requireOwner, validateBody(schemas.adminUserId), async (req, res) => {
    const roomId = req.params.roomId;
    const targetUserId = req.body.userId;

    // remove from roomUsers map (online list)
    if (roomUsers.has(roomId)) roomUsers.get(roomId).delete(targetUserId);

    // kick socket if active
    const socketId = activeUsers.get(targetUserId);
    if (socketId) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
            s.emit('kicked', { roomId, reason: 'kicked' });
            s.leave(roomId);
        }
    }

    res.json({ message: 'User kicked (online users only)' });
});

// Location history API (registered users)
app.get('/api/rooms/:roomId/location-history', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        const room = rooms.find(r => r.id === roomId);
        if (!room) return res.status(404).json({ message: 'Room not found' });
        if (!room.members.includes(userId)) return res.status(403).json({ message: 'You are not a member of this room' });

        const settings = roomSettings.get(roomId) || {};
        if (!settings.locationHistoryEnabled) return res.json({ roomId, enabled: false, points: [] });
        if (!isMongoConnected()) return res.json({ roomId, enabled: true, points: [] });

        const limit = Math.min(parseInt(req.query.limit || '200', 10) || 200, 1000);
        const since = req.query.since ? new Date(String(req.query.since)) : null;

        const query = { roomId };
        if (since && !Number.isNaN(since.getTime())) query.timestamp = { $gte: since };

        const docs = await LocationPing.find(query).sort({ timestamp: 1 }).limit(limit).lean();
        res.json({ roomId, enabled: true, points: docs });
    } catch (err) {
        console.error('Location history fetch error:', err);
        res.status(500).json({ message: 'Server error while fetching location history' });
    }
});

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.io
const io = socketIo(server);

// Socket.io connection handler
io.on('connection', (socket) => {
    console.log('New client connected');

    const isInRoom = (roomId) => socket.rooms.has(roomId);
    
    // Join room
    socket.on('join-room', (data) => {
        const { userId, username, roomId, isGuest } = data || {};

        if (!roomId || !userId || !username) {
            return;
        }
        
        // Enforce bans for registered users
        const settings = roomSettings.get(roomId) || {};
        if (!isGuest && settings.bannedUserIds && settings.bannedUserIds.includes(userId)) {
            socket.emit('kicked', { roomId, reason: 'banned' });
            return;
        }

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
        
        // Collect all users in the room, including guests and registered users
        const onlineUsers = [];
        
        // Add all registered users from this room
        if (room && room.members) {
            for (const memberId of room.members) {
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
        
        // Add current user if they're a guest or not already in the list
        const userAlreadyInList = onlineUsers.some(u => u.id === userId);
        if (isGuest || !userAlreadyInList) {
            onlineUsers.push({
                id: userId,
                username: username,
                isGuest: isGuest,
                isOwner: room && room.ownerId === userId
            });
        }
        
        // Add any active guest users in this room
        const roomGuestUsers = Array.from(roomUsers.get(roomId) || [])
            .filter(id => id.startsWith('guest_') && id !== userId);
            
        for (const guestId of roomGuestUsers) {
            // Find the socket for this guest user
            const guestSocketId = Array.from(io.sockets.sockets.keys())
                .find(socketId => {
                    const socket = io.sockets.sockets.get(socketId);
                    return socket && socket.rooms.has(roomId) && socket.data && socket.data.userId === guestId;
                });
                
            if (guestSocketId) {
                const guestSocket = io.sockets.sockets.get(guestSocketId);
                if (guestSocket && guestSocket.data && guestSocket.data.username) {
                    onlineUsers.push({
                        id: guestId,
                        username: guestSocket.data.username,
                        isGuest: true,
                        isOwner: false
                    });
                }
            }
        }
        
        // Store user data in socket for later reference
        socket.data = { userId, username, isGuest, roomId };
        
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
        const { userId, username, roomId, latitude, longitude, accuracy, isGuest } = data || {};

        // Basic validation
        if (!roomId || !isInRoom(roomId)) return;
        if (!socket.data || socket.data.userId !== userId) return;

        // Broadcast location to all users in the room
        io.to(roomId).emit('receive-location', {
            userId,
            username,
            latitude,
            longitude,
            accuracy,
            isGuest
        });

        // Optional location history (registered users only)
        const settings = roomSettings.get(roomId) || {};
        if (!isGuest && settings.locationHistoryEnabled && isMongoConnected()) {
            const doc = {
                roomId,
                userId,
                latitude: Number(latitude),
                longitude: Number(longitude),
                accuracy: accuracy != null ? Number(accuracy) : null,
                timestamp: new Date()
            };
            LocationPing.create(doc)
                .then(async () => {
                    // cap to last 500 points per user per room
                    const count = await LocationPing.countDocuments({ roomId, userId });
                    if (count > 500) {
                        const toDelete = count - 500;
                        const old = await LocationPing.find({ roomId, userId }).sort({ timestamp: 1 }).limit(toDelete).select({ _id: 1 }).lean();
                        if (old.length) {
                            await LocationPing.deleteMany({ _id: { $in: old.map(o => o._id) } });
                        }
                    }
                })
                .catch(err => console.error('Location history write error:', err));
        }
    });

    // Request location from a specific user
    socket.on('request-location', (data) => {
        const { targetUserId, roomId } = data || {};

        if (!roomId || !targetUserId || !isInRoom(roomId)) return;
        const settings = roomSettings.get(roomId) || {};
        const isOwner = settings && socket.data && rooms.find(r => r.id === roomId)?.ownerId === socket.data.userId;
        if (settings.locationRequestsDisabled && !isOwner) return;

        // Find the socket for the target user
        const targetSocketId = activeUsers.get(targetUserId);
        if (targetSocketId) {
            const targetSocket = io.sockets.sockets.get(targetSocketId);
            if (targetSocket) {
                // Forward the request to the target user
                targetSocket.emit('location-requested', { roomId });
            }
        } else if (targetUserId.startsWith('guest_')) {
            // Try to find guest socket by iterating through sockets in the room
            const roomSockets = io.sockets.adapter.rooms.get(roomId);
            if (roomSockets) {
                for (const socketId of roomSockets) {
                    const socket = io.sockets.sockets.get(socketId);
                    if (socket && socket.data && socket.data.userId === targetUserId) {
                        socket.emit('location-requested', { roomId });
                        break;
                    }
                }
            }
        }
    });

    // Send message
    socket.on('send-message', (data) => {
        const { userId, username, roomId, message, timestamp, isGuest } = data || {};

        if (!roomId || !message || !isInRoom(roomId)) return;
        if (!socket.data || socket.data.userId !== userId) return;

        const settings = roomSettings.get(roomId) || {};
        const isOwner = settings && rooms.find(r => r.id === roomId)?.ownerId === userId;
        if (settings.chatMuted && !isOwner) return;

        const cleanedMessage = sanitizeHtml(String(message), { allowedTags: [], allowedAttributes: {} }).trim().slice(0, 500);
        if (!cleanedMessage) return;

        // Create message object
        const messageObj = {
            userId,
            username,
            message: cleanedMessage,
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
        
        // Find user by socket ID or socket data
        let disconnectedUserId = null;
        
        // First try to get user ID from socket data
        if (socket.data && socket.data.userId) {
            disconnectedUserId = socket.data.userId;
        } else {
            // If not in socket data, check activeUsers map
            for (const [userId, socketId] of activeUsers.entries()) {
                if (socketId === socket.id) {
                    disconnectedUserId = userId;
                    break;
                }
            }
        }
        
        if (disconnectedUserId) {
            // Remove user from active users
            activeUsers.delete(disconnectedUserId);
            
            // Notify all rooms the user was in
            const roomsToUpdate = new Set();
            
            // Check user's registered rooms
            if (userRooms.has(disconnectedUserId)) {
                for (const roomId of userRooms.get(disconnectedUserId)) {
                    roomsToUpdate.add(roomId);
                }
            }
            
            // Check all rooms for this socket
            for (const room of socket.rooms) {
                // Skip the socket's own room (socket.id)
                if (room !== socket.id) {
                    roomsToUpdate.add(room);
                }
            }
            
            // Update each room
            for (const roomId of roomsToUpdate) {
                // Remove user from room users
                if (roomUsers.has(roomId)) {
                    roomUsers.get(roomId).delete(disconnectedUserId);
                    
                    // Find the room for owner check
                    const room = rooms.find(r => r.id === roomId);
                    if (!room) continue;
                    
                    // Get all registered users for this room
                    const registeredUsers = room.members.map(id => {
                        const user = users.find(u => u.id === id);
                        return user ? {
                            id,
                            username: user.username,
                            isGuest: false,
                            isOwner: room.ownerId === id
                        } : null;
                    }).filter(Boolean);
                    
                    // Get active guest users for this room
                    const guestUsers = Array.from(roomUsers.get(roomId) || [])
                        .filter(id => id.startsWith('guest_'))
                        .map(guestId => {
                            // Find socket for this guest
                            const guestSocketId = Array.from(io.sockets.sockets.keys())
                                .find(socketId => {
                                    const socket = io.sockets.sockets.get(socketId);
                                    return socket && socket.rooms.has(roomId) && 
                                           socket.data && socket.data.userId === guestId;
                                });
                                
                            if (guestSocketId) {
                                const guestSocket = io.sockets.sockets.get(guestSocketId);
                                if (guestSocket && guestSocket.data) {
                                    return {
                                        id: guestId,
                                        username: guestSocket.data.username,
                                        isGuest: true,
                                        isOwner: false
                                    };
                                }
                            }
                            return null;
                        }).filter(Boolean);
                    
                    // Combine registered and guest users
                    const roomUsersList = [...registeredUsers, ...guestUsers];
                    
                    // Send updated user list to all clients in the room
                    io.to(roomId).emit('online-users', roomUsersList);
                    
                    // Notify room that user disconnected
                    io.to(roomId).emit('user-disconnected', disconnectedUserId);
                }
            }
        }
    });
});

// Start server with error handling
const start = async () => {
    try {
        if (isMongoConfigured()) {
            try {
                await connectMongo();
                console.log('MongoDB connected');

                // Warm in-memory caches used by existing socket logic
                const [userDocs, roomDocs] = await Promise.all([
                    User.find({}).lean(),
                    Room.find({}).lean()
                ]);

                users.length = 0;
                rooms.length = 0;

                for (const u of userDocs) {
                    users.push({
                        id: u._id.toString(),
                        email: u.email,
                        username: u.username,
                        password: u.passwordHash,
                        createdAt: u.createdAt || new Date()
                    });
                }

                for (const r of roomDocs) {
                    rooms.push({
                        id: r.roomId,
                        name: r.name,
                        description: r.description || '',
                        ownerId: r.ownerId ? r.ownerId.toString() : null,
                        createdAt: r.createdAt || new Date(),
                        members: (r.members || []).map(m => m.toString())
                    });
                }
            } catch (mongoErr) {
                console.error('MongoDB connection failed; continuing with in-memory storage:', mongoErr.message || mongoErr);
            }
        } else {
            console.log('MongoDB disabled (no MONGODB_URI set)');
        }

        server.listen(PORT, HOST, () => {
            console.log(`Server running on ${HOST}:${PORT}`);
        }).on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                const newPort = parseInt(PORT) + 1;
                console.error(`Port ${PORT} is already in use. Trying port ${newPort}...`);
                server.listen(newPort, HOST, () => {
                    console.log(`Server running on ${HOST}:${newPort}`);
                });
            } else {
                console.error('Server error:', err);
            }
        });
    } catch (err) {
        console.error('Startup error:', err);
        process.exit(1);
    }
};

start();

// Set increased timeout values to prevent connection reset issues
server.keepAliveTimeout = 120000; // 120 seconds
server.headersTimeout = 120000; // 120 seconds
