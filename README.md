# ISTE Club Admin Portal

A modern web-based admin dashboard for managing ISTE club events, registrations, and participants.

## Features

- 🔐 Secure Firebase Authentication
- 📊 Dashboard with event statistics
- 👥 Team registration management
- ✅ Bulk actions (verify, delete, email)
- 🗑️ Soft delete with trash recovery
- 📱 Responsive design
- 🔒 Rate limiting & input sanitization

## Tech Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Firebase (Firestore, Authentication)
- **Security**: Client-side rate limiting, XSS protection

## Setup

1. Clone the repository
2. Configure Firebase Security Rules (see below)
3. Open `admin.html` in a web browser or serve via local server

## Firebase Security Rules

Ensure your Firestore has proper security rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Only authenticated admins can read/write
    match /registrations/{docId} {
      allow read, write: if request.auth != null;
    }
    match /trash/{docId} {
      allow read, write: if request.auth != null;
    }
    match /auditLogs/{docId} {
      allow create: if request.auth != null;
      allow read: if request.auth != null;
    }
  }
}
```

## Security

- Firebase API keys are client-safe by design
- All inputs are sanitized before rendering
- Rate limiting prevents abuse
- Session timeout for inactivity

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

Made with ❤️ by ISTE Club
