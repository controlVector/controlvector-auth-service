export interface User {
  id: string
  email: string
  name: string
  avatar_url?: string
  provider: 'email' | 'github' | 'google'
  provider_id?: string
  workspace_id: string
  role: 'owner' | 'admin' | 'member'
  email_verified: boolean
  created_at: string
  updated_at: string
  last_login_at: string
}

export interface Workspace {
  id: string
  name: string
  slug: string
  owner_id: string
  created_at: string
  updated_at: string
}

export interface RefreshToken {
  id: string
  user_id: string
  token_hash: string
  expires_at: string
  created_at: string
  last_used_at?: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface SignUpRequest {
  email: string
  password: string
  name: string
}

export interface AuthResponse {
  user: User
  access_token: string
  refresh_token: string
  expires_in: number
}

export interface JWTPayload {
  sub: string // user ID
  email: string
  name: string
  workspace_id: string
  role: string
  iat: number
  exp: number
}

export interface OAuthProfile {
  id: string
  email: string
  name: string
  avatar_url?: string
  provider: 'github' | 'google'
}

export interface PasswordResetRequest {
  id: string
  user_id: string
  token_hash: string
  expires_at: string
  created_at: string
  used_at?: string
}

export interface EmailVerificationRequest {
  id: string
  user_id: string
  token_hash: string
  expires_at: string
  created_at: string
  verified_at?: string
}

export class AuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400,
    public context?: any
  ) {
    super(message)
    this.name = 'AuthError'
  }
}

export class ValidationError extends AuthError {
  constructor(message: string, public field: string) {
    super(message, 'VALIDATION_ERROR', 400, { field })
    this.name = 'ValidationError'
  }
}

export class UnauthorizedError extends AuthError {
  constructor(message: string = 'Unauthorized') {
    super(message, 'UNAUTHORIZED', 401)
    this.name = 'UnauthorizedError'
  }
}

export class ForbiddenError extends AuthError {
  constructor(message: string = 'Forbidden') {
    super(message, 'FORBIDDEN', 403)
    this.name = 'ForbiddenError'
  }
}

export class NotFoundError extends AuthError {
  constructor(message: string = 'Not found') {
    super(message, 'NOT_FOUND', 404)
    this.name = 'NotFoundError'
  }
}

export class ConflictError extends AuthError {
  constructor(message: string, public resource: string) {
    super(message, 'CONFLICT', 409, { resource })
    this.name = 'ConflictError'
  }
}

export class RateLimitError extends AuthError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 'RATE_LIMIT', 429)
    this.name = 'RateLimitError'
  }
}

export interface AuthConfig {
  port: number
  host: string
  log_level: string
  
  // JWT Configuration
  jwt_secret: string
  jwt_expires_in: string
  refresh_token_expires_in: string
  
  // Database
  database_url: string
  redis_url?: string
  
  // OAuth Providers
  github_client_id?: string
  github_client_secret?: string
  google_client_id?: string
  google_client_secret?: string
  
  // Email Service
  smtp_host?: string
  smtp_port?: number
  smtp_user?: string
  smtp_password?: string
  smtp_from?: string
  
  // Security
  bcrypt_rounds: number
  password_min_length: number
  enable_cors: boolean
  allowed_origins: string[]
  
  // Rate Limiting
  enable_rate_limiting: boolean
  rate_limit_max: number
  rate_limit_time_window: string
  
  // Frontend URLs
  frontend_url: string
  auth_callback_url: string
}