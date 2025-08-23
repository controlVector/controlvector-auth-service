import { FastifyInstance } from 'fastify'
import { AuthConfig } from '../types'
import { DatabaseService } from '../services/DatabaseService'
import { AuthService } from '../services/AuthService'
import { 
  createAuthController,
  login,
  signUp,
  refresh,
  logout,
  getOAuthUrl,
  handleOAuthCallback,
  requestPasswordReset,
  resetPassword,
  getCurrentUser,
  updateProfile,
  changePassword,
  resendVerificationEmail,
  verifyEmail,
  healthCheck
} from '../controllers/AuthController'
import { authenticateToken, optionalAuth, requireRole } from '../middleware/auth'

export async function registerRoutes(fastify: FastifyInstance, config: AuthConfig) {
  const db = new DatabaseService(config.database_url)
  const authService = new AuthService(db, config)
  const controller = createAuthController(authService)

  // Health check (public)
  fastify.get('/health', {
    handler: healthCheck.bind(controller)
  })

  // Authentication routes (public)
  fastify.post('/auth/login', {
    handler: login.bind(controller)
  })

  fastify.post('/auth/signup', {
    handler: signUp.bind(controller)
  })

  fastify.post('/auth/refresh', {
    handler: refresh.bind(controller)
  })

  // OAuth routes (public)
  fastify.get('/auth/oauth/:provider/url', {
    handler: getOAuthUrl.bind(controller)
  })

  fastify.post('/auth/oauth/:provider/callback', {
    handler: handleOAuthCallback.bind(controller)
  })

  // Password reset routes (public)
  fastify.post('/auth/password/reset-request', {
    handler: requestPasswordReset.bind(controller)
  })

  fastify.post('/auth/password/reset', {
    handler: resetPassword.bind(controller)
  })

  // Email verification routes
  fastify.post('/auth/verify', {
    handler: verifyEmail.bind(controller)
  })

  // Protected routes - require authentication
  fastify.register(async function (fastify) {
    // Add authentication middleware to all routes in this scope
    fastify.addHook('preHandler', authenticateToken)

    // Logout
    fastify.post('/auth/logout', {
      handler: logout.bind(controller)
    })

    // User profile
    fastify.get('/auth/me', {
      handler: getCurrentUser.bind(controller)
    })

    fastify.patch('/auth/me', {
      handler: updateProfile.bind(controller)
    })

    fastify.patch('/auth/me/password', {
      handler: changePassword.bind(controller)
    })

    // Email verification
    fastify.post('/auth/verify/resend', {
      handler: resendVerificationEmail.bind(controller)
    })
  })

  // Cleanup expired tokens periodically
  setInterval(async () => {
    try {
      await db.cleanupExpiredTokens()
    } catch (error) {
      fastify.log.error(error, 'Failed to cleanup expired tokens')
    }
  }, 60 * 60 * 1000) // Every hour
}