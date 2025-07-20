# Real-Time Location Tracker

A modern real-time location tracking application with user accounts, room-based tracking, and chat functionality. Users can create accounts, create rooms, and invite friends to join their rooms to track each other's locations in real-time with high accuracy.

## Features

- **User Authentication**
  - Register and login with email and display name
  - Secure password storage with bcrypt
  - JWT-based authentication

- **Room Management**
  - Create and manage rooms with simple 6-digit IDs
  - Join rooms using 6-digit room IDs
  - Share rooms via WhatsApp or email

- **Real-Time Location Tracking**
  - High-precision location tracking with accuracy indicators
  - Visual map display with custom user markers
  - Member list showing all users in the room
  - Location accuracy information and refresh option

- **Communication**
  - In-room chat functionality
  - Real-time updates

- **Responsive Design**
  - Mobile-friendly interface
  - Dark mode support

## Technologies Used

- **Frontend**: HTML, CSS, JavaScript, Bootstrap, Leaflet.js
- **Backend**: Node.js, Express.js
- **Real-time Communication**: Socket.IO
- **Authentication**: JWT, bcrypt
- **Templating**: EJS

## License

This project is licensed under the ISC License. 