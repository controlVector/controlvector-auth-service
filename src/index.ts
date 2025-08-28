import fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import cookie from '@fastify/cookie'
import rateLimit from '@fastify/rate-limit'
import jwt from '@fastify/jwt'
import dotenv from 'dotenv'
import { registerRoutes } from './routes'
import { AuthConfig } from './types'

dotenv.config()

const config: AuthConfig = {
  port: parseInt(process.env.PORT || '3002'),
  host: process.env.HOST || '0.0.0.0',
  log_level: process.env.LOG_LEVEL || 'info',
  
  // JWT Configuration
  jwt_secret: process.env.JWT_SECRET || 'controlvector-auth-development-secret-key',
  jwt_expires_in: process.env.JWT_EXPIRES_IN || (process.env.NODE_ENV === 'development' ? '8h' : '1h'),
  refresh_token_expires_in: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d',
  
  // Database (using in-memory store for demo)
  database_url: process.env.DATABASE_URL || '',
  redis_url: process.env.REDIS_URL,
  
  // OAuth Providers (demo values)
  github_client_id: process.env.GITHUB_CLIENT_ID,
  github_client_secret: process.env.GITHUB_CLIENT_SECRET,
  google_client_id: process.env.GOOGLE_CLIENT_ID,
  google_client_secret: process.env.GOOGLE_CLIENT_SECRET,
  
  // Email Service
  smtp_host: process.env.SMTP_HOST,
  smtp_port: parseInt(process.env.SMTP_PORT || '587'),
  smtp_user: process.env.SMTP_USER,
  smtp_password: process.env.SMTP_PASSWORD,
  smtp_from: process.env.SMTP_FROM || 'noreply@controlvector.dev',
  
  // Security
  bcrypt_rounds: parseInt(process.env.BCRYPT_ROUNDS || '12'),
  password_min_length: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
  enable_cors: process.env.ENABLE_CORS !== 'false',
  allowed_origins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  
  // Rate Limiting
  enable_rate_limiting: process.env.ENABLE_RATE_LIMITING !== 'false',
  rate_limit_max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  rate_limit_time_window: process.env.RATE_LIMIT_TIME_WINDOW || '15m',
  
  // Frontend URLs
  frontend_url: process.env.FRONTEND_URL || 'http://localhost:3000',
  auth_callback_url: process.env.AUTH_CALLBACK_URL || 'http://localhost:3002'
}

const server = fastify({
  logger: {
    level: config.log_level
  }
})

async function start() {
  try {
    // CORS configuration
    if (config.enable_cors) {
      await server.register(cors, {
        origin: config.allowed_origins,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
      })
    }

    // Security headers
    await server.register(helmet, {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "https:"],
        }
      }
    })

    // Cookie support
    await server.register(cookie, {
      secret: config.jwt_secret,
      parseOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
      }
    })

    // JWT authentication
    await server.register(jwt, {
      secret: config.jwt_secret
    })

    // Rate limiting
    if (config.enable_rate_limiting) {
      await server.register(rateLimit, {
        max: config.rate_limit_max,
        timeWindow: config.rate_limit_time_window,
        errorResponseBuilder: (request, context) => ({
          success: false,
          error: 'Rate limit exceeded',
          retryAfter: Math.round(context.ttl / 1000)
        })
      })
    }

    // Global error handler
    server.setErrorHandler(async (error, request, reply) => {
      request.log.error(error)

      // Don't expose internal errors in production
      if (process.env.NODE_ENV === 'production') {
        reply.code(500).send({
          success: false,
          error: 'Internal server error'
        })
      } else {
        reply.code(500).send({
          success: false,
          error: error.message,
          stack: error.stack
        })
      }
    })

    // Register routes
    await registerRoutes(server, config)

    // Start server
    const address = await server.listen({
      port: config.port,
      host: config.host
    })

    server.log.info(`ControlVector Auth Service listening at ${address}`)
    server.log.info('Configuration:')
    server.log.info(`- Environment: ${process.env.NODE_ENV || 'development'}`)
    server.log.info(`- CORS: ${config.enable_cors ? 'enabled' : 'disabled'}`)
    server.log.info(`- Rate Limiting: ${config.enable_rate_limiting ? 'enabled' : 'disabled'}`)
    server.log.info(`- Frontend URL: ${config.frontend_url}`)
    server.log.info(`- Database: ${config.database_url ? 'configured' : 'in-memory'}`)

  } catch (error) {
    server.log.error(error, 'Failed to start auth service')
    process.exit(1)
  }
}

// Graceful shutdown
const gracefulShutdown = async (signal: string) => {
  server.log.info(`Received ${signal}, gracefully shutting down...`)
  try {
    await server.close()
    process.exit(0)
  } catch (error) {
    server.log.error(error, 'Error during graceful shutdown')
    process.exit(1)
  }
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'))
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))

start()
