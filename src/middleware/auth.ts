import { FastifyRequest, FastifyReply } from 'fastify'
import { UnauthorizedError } from '../types'

export async function authenticateToken(
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const authHeader = request.headers.authorization
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('Access token required')
    }

    const token = authHeader.substring(7)
    
    if (!token) {
      throw new UnauthorizedError('Access token required')
    }

    // Decode JWT token (simplified for demo - in production use proper JWT verification)
    let payload
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf-8')
      payload = JSON.parse(decoded)
    } catch (error) {
      throw new UnauthorizedError('Invalid access token')
    }

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedError('Access token expired')
    }

    // Attach user to request
    ;(request as any).user = payload

  } catch (error) {
    if (error instanceof UnauthorizedError) {
      reply.code(error.statusCode).send({
        success: false,
        error: error.message,
        code: error.code
      })
      return
    }

    reply.code(401).send({
      success: false,
      error: 'Authentication failed'
    })
  }
}

export async function optionalAuth(
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    const authHeader = request.headers.authorization
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7)
      
      try {
        const decoded = Buffer.from(token, 'base64').toString('utf-8')
        const payload = JSON.parse(decoded)
        
        // Only attach if not expired
        if (!payload.exp || payload.exp >= Math.floor(Date.now() / 1000)) {
          ;(request as any).user = payload
        }
      } catch (error) {
        // Ignore invalid tokens in optional auth
      }
    }
  } catch (error) {
    // Ignore errors in optional auth
  }
}

export function requireRole(allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user
    
    if (!user) {
      reply.code(401).send({
        success: false,
        error: 'Authentication required'
      })
      return
    }

    if (!allowedRoles.includes(user.role)) {
      reply.code(403).send({
        success: false,
        error: 'Insufficient permissions'
      })
      return
    }
  }
}