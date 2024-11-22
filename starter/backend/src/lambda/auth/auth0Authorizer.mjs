import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://dev-zob7vfq106w5ehjh.eu.auth0.com/.well-known/jwks.json'

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  try {
    if (!authHeader) {
      throw new Error('No authentication header provided')
    }

    const token = getToken(authHeader)
    if (!token) {
      throw new Error('No token found in the authentication header')
    }

    const jwt = jsonwebtoken.decode(token, { complete: true })
    if (!jwt) {
      throw new Error('Invalid token')
    }

    const response = await Axios.get(jwksUrl)
    const keys = response.data.keys
    if (!keys || keys.length === 0) {
      throw new Error('JWKS endpoint has no keys')
    }

    const signingKey = keys.find(key => key.kid === jwt.header.kid)
    if (!signingKey) {
      throw new Error('No signing key found for the token')
    }

    const pemData = signingKey.x5c[0]
    const cert = `-----BEGIN CERTIFICATE-----\n${pemData}\n-----END CERTIFICATE-----\n`
    const verifiedToken = jsonwebtoken.verify(token, cert, { algorithms: ['RS256'] })

    logger.info('Verified token: ', verifiedToken)
    return verifiedToken
  } catch (error) {
    logger.error('Token verification failed: ', error)
    throw new Error('Token verification failed')
  }
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
