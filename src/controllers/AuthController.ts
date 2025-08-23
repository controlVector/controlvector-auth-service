import { FastifyRequest, FastifyReply } from 'fastify'
import { AuthService } from '../services/AuthService'
import { z } from 'zod'
import { AuthError } from '../types'

const LoginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
})

const SignUpSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
})

const RefreshTokenSchema = z.object({
  refresh_token: z.string().min(1, 'Refresh token is required')
})

const PasswordResetRequestSchema = z.object({
  email: z.string().email('Invalid email address')
})

const PasswordResetSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
})

const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
})

const UpdateProfileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').optional(),
  email: z.string().email('Invalid email address').optional()
})

interface AuthController {
  authService: AuthService
}

export function createAuthController(authService: AuthService): AuthController {
  return { authService }
}

// Email/Password Authentication
export async function login(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const body = LoginSchema.parse(request.body)
    const result = await this.authService.login(body)

    // Set refresh token as HTTP-only cookie
    reply.setCookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    reply.send({
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        expires_in: result.expires_in
      }
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function signUp(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const body = SignUpSchema.parse(request.body)
    const result = await this.authService.signUp(body)

    // Set refresh token as HTTP-only cookie
    reply.setCookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    reply.code(201).send({
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        expires_in: result.expires_in
      }
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// Token Management
export async function refresh(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    // Try to get refresh token from body or cookie
    const bodyData = request.body as any
    const refreshToken = bodyData?.refresh_token || request.cookies.refresh_token

    if (!refreshToken) {
      reply.code(400).send({
        success: false,
        error: 'Refresh token is required'
      })
      return
    }

    const result = await this.authService.refreshToken(refreshToken)

    // Set new refresh token as HTTP-only cookie
    reply.setCookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    reply.send({
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        expires_in: result.expires_in
      }
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function logout(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const user = (request as any).user
    const refreshToken = (request.body as any)?.refresh_token || request.cookies.refresh_token

    if (user?.sub) {
      await this.authService.logout(user.sub, refreshToken)
    }

    // Clear refresh token cookie
    reply.clearCookie('refresh_token')

    reply.send({
      success: true,
      message: 'Logged out successfully'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// OAuth
export async function getOAuthUrl(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const { provider } = request.params as { provider: string }
    
    if (!['github', 'google'].includes(provider)) {
      reply.code(400).send({
        success: false,
        error: 'Unsupported OAuth provider'
      })
      return
    }

    // Generate OAuth URLs (this would integrate with actual OAuth providers)
    const baseUrls = {
      github: 'https://github.com/login/oauth/authorize',
      google: 'https://accounts.google.com/oauth2/v2/auth'
    }

    const state = Math.random().toString(36).substring(7)
    const clientIds = {
      github: process.env.GITHUB_CLIENT_ID || 'demo-client-id',
      google: process.env.GOOGLE_CLIENT_ID || 'demo-client-id'
    }

    const redirectUri = `${process.env.AUTH_CALLBACK_URL || 'http://localhost:3002'}/auth/oauth/${provider}/callback`
    
    const params = new URLSearchParams({
      client_id: clientIds[provider as keyof typeof clientIds],
      redirect_uri: redirectUri,
      scope: provider === 'github' ? 'user:email' : 'email profile',
      state,
      response_type: 'code'
    })

    const url = `${baseUrls[provider as keyof typeof baseUrls]}?${params.toString()}`

    reply.send({
      success: true,
      data: { url, state }
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function handleOAuthCallback(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const { provider } = request.params as { provider: string }
    const { code, state } = request.body as { code: string; state: string }

    if (!['github', 'google'].includes(provider)) {
      reply.code(400).send({
        success: false,
        error: 'Unsupported OAuth provider'
      })
      return
    }

    // Mock OAuth profile for demo (in production, exchange code for access token and fetch profile)
    const mockProfile = {
      id: `${provider}_${Math.random().toString(36).substring(7)}`,
      email: 'demo@example.com',
      name: 'Demo User',
      avatar_url: `https://via.placeholder.com/150?text=${provider.toUpperCase()}`,
      provider: provider as 'github' | 'google'
    }

    const result = await this.authService.handleOAuthCallback(provider as any, mockProfile)

    // Set refresh token as HTTP-only cookie
    reply.setCookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    reply.send({
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        expires_in: result.expires_in
      }
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// Password Management
export async function requestPasswordReset(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const body = PasswordResetRequestSchema.parse(request.body)
    await this.authService.requestPasswordReset(body.email)

    reply.send({
      success: true,
      message: 'Password reset link sent to email if account exists'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function resetPassword(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const body = PasswordResetSchema.parse(request.body)
    await this.authService.resetPassword(body.token, body.password)

    reply.send({
      success: true,
      message: 'Password reset successfully'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// User Management
export async function getCurrentUser(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const user = (request as any).user
    const userData = await this.authService.getCurrentUser(user.sub)

    reply.send({
      success: true,
      data: userData
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function updateProfile(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const user = (request as any).user
    const body = UpdateProfileSchema.parse(request.body)
    
    const updatedUser = await this.authService.updateProfile(user.sub, body)

    reply.send({
      success: true,
      data: updatedUser
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function changePassword(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const user = (request as any).user
    const body = ChangePasswordSchema.parse(request.body)
    
    await this.authService.changePassword(user.sub, body.currentPassword, body.newPassword)

    reply.send({
      success: true,
      message: 'Password changed successfully'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// Email Verification
export async function resendVerificationEmail(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const user = (request as any).user
    await this.authService.resendVerificationEmail(user.sub)

    reply.send({
      success: true,
      message: 'Verification email sent'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

export async function verifyEmail(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const { token } = request.body as { token: string }
    
    if (!token) {
      reply.code(400).send({
        success: false,
        error: 'Verification token is required'
      })
      return
    }

    await this.authService.verifyEmail(token)

    reply.send({
      success: true,
      message: 'Email verified successfully'
    })
  } catch (error) {
    handleError(error, reply, request)
  }
}

// Health Check
export async function healthCheck(
  this: AuthController,
  request: FastifyRequest,
  reply: FastifyReply
) {
  reply.send({
    success: true,
    service: 'controlvector-auth',
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  })
}

// Error Handler
function handleError(error: any, reply: FastifyReply, request: FastifyRequest) {
  request.log.error(error)

  if (error instanceof z.ZodError) {
    reply.code(400).send({
      success: false,
      error: 'Validation error',
      details: error.errors.map(e => ({
        field: e.path.join('.'),
        message: e.message
      }))
    })
    return
  }

  if (error instanceof AuthError) {
    reply.code(error.statusCode).send({
      success: false,
      error: error.message,
      code: error.code
    })
    return
  }

  // Generic error
  reply.code(500).send({
    success: false,
    error: 'Internal server error'
  })
}