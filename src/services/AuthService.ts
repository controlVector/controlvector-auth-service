import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { DatabaseService } from './DatabaseService'
import { User, LoginRequest, SignUpRequest, AuthResponse, OAuthProfile, AuthConfig, AuthError, ConflictError, UnauthorizedError, NotFoundError } from '../types'
import { v4 as uuidv4 } from 'uuid'

export class AuthService {
  private db: DatabaseService
  private config: AuthConfig

  constructor(db: DatabaseService, config: AuthConfig) {
    this.db = db
    this.config = config
  }

  // Email/Password Authentication
  async signUp(signUpData: SignUpRequest): Promise<AuthResponse> {
    const { email, password, name } = signUpData

    // Check if user already exists
    const existingUser = await this.db.getUserByEmail(email.toLowerCase())
    if (existingUser) {
      throw new ConflictError('User with this email already exists', 'email')
    }

    // Validate password strength
    this.validatePassword(password)

    // Hash password
    const passwordHash = await bcrypt.hash(password, this.config.bcrypt_rounds)

    // Create workspace for new user
    const workspaceSlug = this.generateWorkspaceSlug(name)
    const workspace = await this.db.createWorkspace({
      name: `${name}'s Workspace`,
      slug: workspaceSlug,
      owner_id: '' // Will be updated after user creation
    })

    // Create user
    const user = await this.db.createUser({
      email: email.toLowerCase(),
      name: name.trim(),
      provider: 'email',
      workspace_id: workspace.id,
      role: 'owner',
      email_verified: false,
      last_login_at: new Date().toISOString(),
      password_hash: passwordHash // Store password hash
    } as any)

    // Update workspace with actual user ID
    await this.db.updateUser(user.id, { workspace_id: workspace.id })

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user)

    return {
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: this.parseExpiration(this.config.jwt_expires_in)
    }
  }

  async login(loginData: LoginRequest): Promise<AuthResponse> {
    const { email, password } = loginData

    // Find user
    const user = await this.db.getUserByEmail(email.toLowerCase())
    if (!user || user.provider !== 'email') {
      throw new UnauthorizedError('Invalid email or password')
    }

    // Verify password (stored in user record for in-memory demo)
    const isValidPassword = await bcrypt.compare(password, (user as any).password_hash || 'invalid')
    if (!isValidPassword) {
      throw new UnauthorizedError('Invalid email or password')
    }

    // Update last login
    await this.db.updateUser(user.id, { last_login_at: new Date().toISOString() })

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user)

    return {
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: this.parseExpiration(this.config.jwt_expires_in)
    }
  }

  // OAuth Authentication
  async handleOAuthCallback(provider: 'github' | 'google', profile: OAuthProfile): Promise<AuthResponse> {
    // Check if user exists with this provider
    let user = await this.db.getUserByProvider(provider, profile.id)
    
    if (!user) {
      // Check if user exists with same email
      const existingUser = await this.db.getUserByEmail(profile.email.toLowerCase())
      
      if (existingUser) {
        // Link OAuth account to existing user
        user = await this.db.updateUser(existingUser.id, {
          provider_id: profile.id,
          avatar_url: profile.avatar_url,
          last_login_at: new Date().toISOString()
        })
      } else {
        // Create new user
        const workspaceSlug = this.generateWorkspaceSlug(profile.name)
        const workspace = await this.db.createWorkspace({
          name: `${profile.name}'s Workspace`,
          slug: workspaceSlug,
          owner_id: '' // Will be updated after user creation
        })

        user = await this.db.createUser({
          email: profile.email.toLowerCase(),
          name: profile.name,
          avatar_url: profile.avatar_url,
          provider,
          provider_id: profile.id,
          workspace_id: workspace.id,
          role: 'owner',
          email_verified: true, // OAuth emails are pre-verified
          last_login_at: new Date().toISOString()
        })
      }
    } else {
      // Update existing OAuth user
      user = await this.db.updateUser(user.id, {
        name: profile.name,
        avatar_url: profile.avatar_url,
        last_login_at: new Date().toISOString()
      })
    }

    if (!user) {
      throw new AuthError('Failed to create or update user', 'OAUTH_ERROR', 500)
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user)

    return {
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: this.parseExpiration(this.config.jwt_expires_in)
    }
  }

  // Token Management
  async refreshToken(refreshTokenValue: string): Promise<AuthResponse> {
    const tokenHash = this.hashToken(refreshTokenValue)
    const refreshTokenRecord = await this.db.getRefreshTokenByHash(tokenHash)

    if (!refreshTokenRecord) {
      throw new UnauthorizedError('Invalid refresh token')
    }

    // Check expiration
    if (new Date(refreshTokenRecord.expires_at) < new Date()) {
      await this.db.deleteRefreshToken(refreshTokenRecord.id)
      throw new UnauthorizedError('Refresh token expired')
    }

    // Get user
    const user = await this.db.getUserById(refreshTokenRecord.user_id)
    if (!user) {
      throw new NotFoundError('User not found')
    }

    // Delete old refresh token
    await this.db.deleteRefreshToken(refreshTokenRecord.id)

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = await this.generateTokens(user)

    return {
      user,
      access_token: accessToken,
      refresh_token: newRefreshToken,
      expires_in: this.parseExpiration(this.config.jwt_expires_in)
    }
  }

  async logout(userId: string, refreshTokenValue?: string): Promise<void> {
    if (refreshTokenValue) {
      // Delete specific refresh token
      const tokenHash = this.hashToken(refreshTokenValue)
      const refreshTokenRecord = await this.db.getRefreshTokenByHash(tokenHash)
      if (refreshTokenRecord) {
        await this.db.deleteRefreshToken(refreshTokenRecord.id)
      }
    } else {
      // Delete all user refresh tokens
      await this.db.deleteUserRefreshTokens(userId)
    }
  }

  // Password Management
  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.db.getUserByEmail(email.toLowerCase())
    if (!user || user.provider !== 'email') {
      // Don't reveal if email exists for security
      return
    }

    const resetToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = this.hashToken(resetToken)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString() // 1 hour

    await this.db.createPasswordReset({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: expiresAt
    })

    // TODO: Send email with reset link
    console.log(`Password reset link: ${this.config.frontend_url}/auth/reset-password?token=${resetToken}`)
  }

  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    const tokenHash = this.hashToken(resetToken)
    const resetRequest = await this.db.getPasswordResetByHash(tokenHash)

    if (!resetRequest) {
      throw new UnauthorizedError('Invalid reset token')
    }

    // Check expiration
    if (new Date(resetRequest.expires_at) < new Date()) {
      throw new UnauthorizedError('Reset token expired')
    }

    // Validate new password
    this.validatePassword(newPassword)

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, this.config.bcrypt_rounds)

    // Update user password
    await this.db.updateUser(resetRequest.user_id, {
      // Store password hash in user record for demo
      ...(resetRequest as any),
      password_hash: passwordHash
    })

    // Mark reset token as used
    await this.db.markPasswordResetUsed(resetRequest.id)

    // Invalidate all refresh tokens for security
    await this.db.deleteUserRefreshTokens(resetRequest.user_id)
  }

  // Email Verification
  async resendVerificationEmail(userId: string): Promise<void> {
    const user = await this.db.getUserById(userId)
    if (!user) {
      throw new NotFoundError('User not found')
    }

    if (user.email_verified) {
      throw new AuthError('Email already verified', 'EMAIL_VERIFIED', 400)
    }

    const verificationToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = this.hashToken(verificationToken)
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours

    await this.db.createEmailVerification({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: expiresAt
    })

    // TODO: Send verification email
    console.log(`Email verification link: ${this.config.frontend_url}/auth/verify-email?token=${verificationToken}`)
  }

  async verifyEmail(verificationToken: string): Promise<void> {
    const tokenHash = this.hashToken(verificationToken)
    const verificationRequest = await this.db.getEmailVerificationByHash(tokenHash)

    if (!verificationRequest) {
      throw new UnauthorizedError('Invalid verification token')
    }

    // Check expiration
    if (new Date(verificationRequest.expires_at) < new Date()) {
      throw new UnauthorizedError('Verification token expired')
    }

    // Update user as verified
    await this.db.updateUser(verificationRequest.user_id, {
      email_verified: true
    })

    // Mark verification as used
    await this.db.markEmailVerified(verificationRequest.id)
  }

  // User Management
  async getCurrentUser(userId: string): Promise<User> {
    const user = await this.db.getUserById(userId)
    if (!user) {
      throw new NotFoundError('User not found')
    }
    return user
  }

  async updateProfile(userId: string, updates: { name?: string; email?: string }): Promise<User> {
    const user = await this.db.getUserById(userId)
    if (!user) {
      throw new NotFoundError('User not found')
    }

    // Check if email is being changed and if it's already taken
    if (updates.email && updates.email !== user.email) {
      const existingUser = await this.db.getUserByEmail(updates.email.toLowerCase())
      if (existingUser && existingUser.id !== userId) {
        throw new ConflictError('Email already in use', 'email')
      }

      // If email is changed, mark as unverified
      updates = {
        ...updates,
        email: updates.email.toLowerCase(),
        email_verified: false
      } as any
    }

    const updatedUser = await this.db.updateUser(userId, updates)
    if (!updatedUser) {
      throw new AuthError('Failed to update user', 'UPDATE_ERROR', 500)
    }

    return updatedUser
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
    const user = await this.db.getUserById(userId)
    if (!user || user.provider !== 'email') {
      throw new UnauthorizedError('Cannot change password for this account')
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, (user as any).password_hash || 'invalid')
    if (!isValidPassword) {
      throw new UnauthorizedError('Current password is incorrect')
    }

    // Validate new password
    this.validatePassword(newPassword)

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, this.config.bcrypt_rounds)

    // Update password
    await this.db.updateUser(userId, {
      // Store password hash for demo
      ...(user as any),
      password_hash: passwordHash
    } as any)

    // Invalidate all refresh tokens for security
    await this.db.deleteUserRefreshTokens(userId)
  }

  // Private Helper Methods
  private async generateTokens(user: User): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      workspace_id: user.workspace_id,
      role: user.role,
      iat: Math.floor(Date.now() / 1000)
    }

    // Generate access token (implement JWT signing)
    const accessToken = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + this.parseExpiration(this.config.jwt_expires_in) }))
      .toString('base64')

    // Generate refresh token
    const refreshTokenValue = crypto.randomBytes(32).toString('hex')
    const tokenHash = this.hashToken(refreshTokenValue)
    const expiresAt = new Date(Date.now() + this.parseExpiration(this.config.refresh_token_expires_in) * 1000).toISOString()

    // Store refresh token
    await this.db.createRefreshToken({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: expiresAt
    })

    return {
      accessToken,
      refreshToken: refreshTokenValue
    }
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex')
  }

  private validatePassword(password: string): void {
    if (password.length < this.config.password_min_length) {
      throw new AuthError(
        `Password must be at least ${this.config.password_min_length} characters long`,
        'WEAK_PASSWORD',
        400
      )
    }

    // Additional password strength checks
    if (!/[A-Z]/.test(password)) {
      throw new AuthError('Password must contain at least one uppercase letter', 'WEAK_PASSWORD', 400)
    }

    if (!/[a-z]/.test(password)) {
      throw new AuthError('Password must contain at least one lowercase letter', 'WEAK_PASSWORD', 400)
    }

    if (!/[0-9]/.test(password)) {
      throw new AuthError('Password must contain at least one number', 'WEAK_PASSWORD', 400)
    }
  }

  private generateWorkspaceSlug(name: string): string {
    return name.toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim()
      + '-' + crypto.randomBytes(3).toString('hex')
  }

  private parseExpiration(expiration: string): number {
    // Parse expressions like '1h', '30m', '7d'
    const match = expiration.match(/^(\d+)([smhd])$/)
    if (!match) return 3600 // Default 1 hour

    const value = parseInt(match[1])
    const unit = match[2]

    switch (unit) {
      case 's': return value
      case 'm': return value * 60
      case 'h': return value * 3600
      case 'd': return value * 86400
      default: return 3600
    }
  }
}