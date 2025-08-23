# ControlVector Auth Service

## Purpose & Integration
- **Primary Role**: Centralized JWT authentication and user management service
- **Service Type**: Core authentication infrastructure for all ControlVector services
- **Key Capabilities**: 
  - JWT token generation and validation with proper signing
  - Email/password authentication with bcrypt hashing
  - OAuth integration (GitHub, Google) for social login
  - User registration, login, password reset workflows
  - Refresh token rotation and secure session management

## Technical Stack
- **Framework**: Fastify with TypeScript for high-performance REST API
- **Authentication**: JWT with proper cryptographic signing using jsonwebtoken
- **Password Security**: bcrypt with configurable rounds (default: 12)
- **Database**: In-memory storage for development, PostgreSQL-ready for production
- **External Integrations**:
  - GitHub OAuth for developer authentication
  - Google OAuth for general user authentication
  - SMTP integration for password reset emails

## Integration Points
- **APIs Provided**:
  - `POST /api/auth/signup` - User registration with email verification
  - `POST /api/auth/login` - Email/password authentication
  - `POST /api/auth/refresh` - JWT token refresh with rotation
  - `POST /api/auth/logout` - Session termination and token invalidation
  - `POST /api/auth/forgot-password` - Password reset initiation
  - `POST /api/auth/reset-password` - Password reset completion
  - `GET /api/auth/me` - Current user profile retrieval
  - `PUT /api/auth/profile` - User profile updates
  - `POST /api/auth/change-password` - Authenticated password change
  - OAuth callbacks for GitHub and Google integration

- **JWT Token Structure**:
  - Payload: `user_id`, `email`, `name`, `workspace_id`, `role`
  - Expiration: Configurable (24h for development, 1h for production)
  - Algorithm: HS256 with shared secret across services

- **Security Features**:
  - Password strength validation (uppercase, lowercase, numbers)
  - Rate limiting protection against brute force attacks
  - CORS configuration for secure cross-origin requests
  - Helmet security headers for XSS/CSRF protection
  - HttpOnly cookies for secure token storage

## Current Status: OPERATIONAL ✅

**Service Running**: Port 3002
**Authentication Flow**: Fully functional ✅
**JWT Implementation**: Fixed and operational ✅ 
**Frontend Integration**: Complete ✅
**Onboarding System**: Successfully integrated ✅

### Recent Fixes (Milestone Achievement)
- **JWT Token Generation**: Fixed from fake base64 encoding to proper JWT signing
- **Secret Synchronization**: Aligned JWT secret with Context Manager service  
- **Token Structure**: Changed from `sub` to `user_id` for service compatibility
- **Development Mode**: Extended token lifetime to 24h for testing convenience

## Development Setup

### Prerequisites
- Node.js 18+
- TypeScript 5.0+
- For production: PostgreSQL 14+, Redis 6+, SMTP server

### Environment Configuration
```env
# Server Configuration
PORT=3002
HOST=0.0.0.0
NODE_ENV=development
LOG_LEVEL=info

# JWT Configuration (CRITICAL: Must match other services)
JWT_SECRET=controlvector-auth-development-secret-key
JWT_EXPIRES_IN=24h
REFRESH_TOKEN_EXPIRES_IN=7d

# Security Settings
BCRYPT_ROUNDS=12
PASSWORD_MIN_LENGTH=8
ENABLE_CORS=true
ALLOWED_ORIGINS=http://localhost:3000
ENABLE_RATE_LIMITING=true

# OAuth Providers
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Email Service
SMTP_HOST=your.smtp.host
SMTP_PORT=587
SMTP_USER=your_smtp_user
SMTP_PASSWORD=your_smtp_password
SMTP_FROM=noreply@controlvector.dev

# Frontend URLs
FRONTEND_URL=http://localhost:3000
AUTH_CALLBACK_URL=http://localhost:3002
```

### Local Development Commands
```bash
# Install dependencies
npm install

# Run in development mode with auto-reload
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run tests
npm test

# Lint code
npm run lint
```

## Deployment & Architecture

### Service Dependencies
- **Context Manager**: Receives and validates JWT tokens for credential storage
- **Watson Service**: Requires authentication for conversation management
- **Atlas Service**: Needs user context for infrastructure operations
- **Frontend**: Consumes authentication APIs for user login/registration

### Database Schema (Production)
- **Users**: `id`, `email`, `name`, `provider`, `workspace_id`, `role`, `email_verified`
- **Workspaces**: `id`, `name`, `slug`, `owner_id` 
- **Refresh Tokens**: `id`, `user_id`, `token_hash`, `expires_at`
- **Password Resets**: `id`, `user_id`, `token_hash`, `expires_at`
- **Email Verifications**: `id`, `user_id`, `token_hash`, `expires_at`

### Security Architecture
- **JWT Signing**: Cryptographically secure with shared secrets across services
- **Password Storage**: bcrypt hashing with salt rounds for rainbow table protection
- **Token Storage**: Secure token hashing for refresh tokens and reset codes
- **Rate Limiting**: Configurable request throttling per endpoint
- **CORS Policy**: Strict origin validation for browser security

### Integration with ControlVector Ecosystem
1. **User Onboarding**: Seamless registration flow integrated with workspace creation
2. **LLM Configuration**: Authentication gates access to credential storage in Context Manager
3. **Service Authentication**: All microservices validate JWT tokens for user identification
4. **OAuth Integration**: Social login reduces friction while maintaining security
5. **Development Mode**: In-memory storage enables rapid local development

This service provides the foundational authentication layer that secures and enables the entire ControlVector platform, ensuring users can safely access and configure their AI infrastructure management tools.