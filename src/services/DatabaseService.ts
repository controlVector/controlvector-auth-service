import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { User, Workspace, RefreshToken, PasswordResetRequest, EmailVerificationRequest } from '../types'
import { v4 as uuidv4 } from 'uuid'

export class DatabaseService {
  private supabase: SupabaseClient | null = null
  private inMemoryStore: {
    users: Map<string, User>
    workspaces: Map<string, Workspace>
    refreshTokens: Map<string, RefreshToken>
    passwordResets: Map<string, PasswordResetRequest>
    emailVerifications: Map<string, EmailVerificationRequest>
  }

  constructor(databaseUrl?: string) {
    if (databaseUrl && databaseUrl.includes('supabase')) {
      // Extract Supabase URL and key from database URL
      const url = databaseUrl.split('|')[0]
      const key = databaseUrl.split('|')[1] || 'your-anon-key'
      this.supabase = createClient(url, key)
    }

    // In-memory store for development/testing
    this.inMemoryStore = {
      users: new Map(),
      workspaces: new Map(),
      refreshTokens: new Map(),
      passwordResets: new Map(),
      emailVerifications: new Map()
    }
  }

  // User Management
  async createUser(userData: Omit<User, 'id' | 'created_at' | 'updated_at'>): Promise<User> {
    const user: User = {
      id: uuidv4(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      ...userData
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('users')
        .insert([user])
        .select()
        .single()

      if (error) throw new Error(`Database error: ${error.message}`)
      return data
    }

    // In-memory fallback
    this.inMemoryStore.users.set(user.id, user)
    return user
  }

  async getUserById(id: string): Promise<User | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('users')
        .select('*')
        .eq('id', id)
        .single()

      if (error) return null
      return data
    }

    return this.inMemoryStore.users.get(id) || null
  }

  async getUserByEmail(email: string): Promise<User | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single()

      if (error) return null
      return data
    }

    // In-memory search
    for (const user of this.inMemoryStore.users.values()) {
      if (user.email === email) return user
    }
    return null
  }

  async getUserByProvider(provider: string, providerId: string): Promise<User | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('users')
        .select('*')
        .eq('provider', provider)
        .eq('provider_id', providerId)
        .single()

      if (error) return null
      return data
    }

    // In-memory search
    for (const user of this.inMemoryStore.users.values()) {
      if (user.provider === provider && user.provider_id === providerId) return user
    }
    return null
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User | null> {
    const updateData = {
      ...updates,
      updated_at: new Date().toISOString()
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('users')
        .update(updateData)
        .eq('id', id)
        .select()
        .single()

      if (error) return null
      return data
    }

    // In-memory update
    const user = this.inMemoryStore.users.get(id)
    if (!user) return null

    const updatedUser = { ...user, ...updateData }
    this.inMemoryStore.users.set(id, updatedUser)
    return updatedUser
  }

  // Workspace Management
  async createWorkspace(workspaceData: Omit<Workspace, 'id' | 'created_at' | 'updated_at'>): Promise<Workspace> {
    const workspace: Workspace = {
      id: uuidv4(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      ...workspaceData
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('workspaces')
        .insert([workspace])
        .select()
        .single()

      if (error) throw new Error(`Database error: ${error.message}`)
      return data
    }

    this.inMemoryStore.workspaces.set(workspace.id, workspace)
    return workspace
  }

  async getWorkspaceById(id: string): Promise<Workspace | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('workspaces')
        .select('*')
        .eq('id', id)
        .single()

      if (error) return null
      return data
    }

    return this.inMemoryStore.workspaces.get(id) || null
  }

  // Refresh Token Management
  async createRefreshToken(tokenData: Omit<RefreshToken, 'id' | 'created_at'>): Promise<RefreshToken> {
    const refreshToken: RefreshToken = {
      id: uuidv4(),
      created_at: new Date().toISOString(),
      ...tokenData
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('refresh_tokens')
        .insert([refreshToken])
        .select()
        .single()

      if (error) throw new Error(`Database error: ${error.message}`)
      return data
    }

    this.inMemoryStore.refreshTokens.set(refreshToken.id, refreshToken)
    return refreshToken
  }

  async getRefreshTokenByHash(tokenHash: string): Promise<RefreshToken | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('refresh_tokens')
        .select('*')
        .eq('token_hash', tokenHash)
        .single()

      if (error) return null
      return data
    }

    for (const token of this.inMemoryStore.refreshTokens.values()) {
      if (token.token_hash === tokenHash) return token
    }
    return null
  }

  async deleteRefreshToken(id: string): Promise<boolean> {
    if (this.supabase) {
      const { error } = await this.supabase
        .from('refresh_tokens')
        .delete()
        .eq('id', id)

      return !error
    }

    return this.inMemoryStore.refreshTokens.delete(id)
  }

  async deleteUserRefreshTokens(userId: string): Promise<boolean> {
    if (this.supabase) {
      const { error } = await this.supabase
        .from('refresh_tokens')
        .delete()
        .eq('user_id', userId)

      return !error
    }

    // In-memory cleanup
    for (const [id, token] of this.inMemoryStore.refreshTokens.entries()) {
      if (token.user_id === userId) {
        this.inMemoryStore.refreshTokens.delete(id)
      }
    }
    return true
  }

  // Password Reset Management
  async createPasswordReset(resetData: Omit<PasswordResetRequest, 'id' | 'created_at'>): Promise<PasswordResetRequest> {
    const passwordReset: PasswordResetRequest = {
      id: uuidv4(),
      created_at: new Date().toISOString(),
      ...resetData
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('password_resets')
        .insert([passwordReset])
        .select()
        .single()

      if (error) throw new Error(`Database error: ${error.message}`)
      return data
    }

    this.inMemoryStore.passwordResets.set(passwordReset.id, passwordReset)
    return passwordReset
  }

  async getPasswordResetByHash(tokenHash: string): Promise<PasswordResetRequest | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('password_resets')
        .select('*')
        .eq('token_hash', tokenHash)
        .eq('used_at', null)
        .single()

      if (error) return null
      return data
    }

    for (const reset of this.inMemoryStore.passwordResets.values()) {
      if (reset.token_hash === tokenHash && !reset.used_at) return reset
    }
    return null
  }

  async markPasswordResetUsed(id: string): Promise<boolean> {
    const usedAt = new Date().toISOString()

    if (this.supabase) {
      const { error } = await this.supabase
        .from('password_resets')
        .update({ used_at: usedAt })
        .eq('id', id)

      return !error
    }

    const reset = this.inMemoryStore.passwordResets.get(id)
    if (reset) {
      reset.used_at = usedAt
      return true
    }
    return false
  }

  // Email Verification Management
  async createEmailVerification(verificationData: Omit<EmailVerificationRequest, 'id' | 'created_at'>): Promise<EmailVerificationRequest> {
    const emailVerification: EmailVerificationRequest = {
      id: uuidv4(),
      created_at: new Date().toISOString(),
      ...verificationData
    }

    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('email_verifications')
        .insert([emailVerification])
        .select()
        .single()

      if (error) throw new Error(`Database error: ${error.message}`)
      return data
    }

    this.inMemoryStore.emailVerifications.set(emailVerification.id, emailVerification)
    return emailVerification
  }

  async getEmailVerificationByHash(tokenHash: string): Promise<EmailVerificationRequest | null> {
    if (this.supabase) {
      const { data, error } = await this.supabase
        .from('email_verifications')
        .select('*')
        .eq('token_hash', tokenHash)
        .eq('verified_at', null)
        .single()

      if (error) return null
      return data
    }

    for (const verification of this.inMemoryStore.emailVerifications.values()) {
      if (verification.token_hash === tokenHash && !verification.verified_at) return verification
    }
    return null
  }

  async markEmailVerified(id: string): Promise<boolean> {
    const verifiedAt = new Date().toISOString()

    if (this.supabase) {
      const { error } = await this.supabase
        .from('email_verifications')
        .update({ verified_at: verifiedAt })
        .eq('id', id)

      return !error
    }

    const verification = this.inMemoryStore.emailVerifications.get(id)
    if (verification) {
      verification.verified_at = verifiedAt
      return true
    }
    return false
  }

  // Cleanup expired tokens
  async cleanupExpiredTokens(): Promise<void> {
    const now = new Date().toISOString()

    if (this.supabase) {
      await Promise.all([
        this.supabase.from('refresh_tokens').delete().lt('expires_at', now),
        this.supabase.from('password_resets').delete().lt('expires_at', now),
        this.supabase.from('email_verifications').delete().lt('expires_at', now),
      ])
      return
    }

    // In-memory cleanup
    for (const [id, token] of this.inMemoryStore.refreshTokens.entries()) {
      if (token.expires_at < now) {
        this.inMemoryStore.refreshTokens.delete(id)
      }
    }

    for (const [id, reset] of this.inMemoryStore.passwordResets.entries()) {
      if (reset.expires_at < now) {
        this.inMemoryStore.passwordResets.delete(id)
      }
    }

    for (const [id, verification] of this.inMemoryStore.emailVerifications.entries()) {
      if (verification.expires_at < now) {
        this.inMemoryStore.emailVerifications.delete(id)
      }
    }
  }
}