import fastifyPlugin from 'fastify-plugin'
import cookie from '@fastify/cookie'
import session from '@fastify/session'
import grant, { GrantResponse, GrantSession } from 'grant'
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify'
import * as B from 'fp-ts/boolean'
import * as E from 'fp-ts/Either'
import * as O from 'fp-ts/Option'
import * as TE from 'fp-ts/TaskEither'
import { pipe } from 'fp-ts/function'
import { inspect } from 'util'
import wcmatch from 'wildcard-match'
import { Issuer, IntrospectionResponse } from 'openid-client'

declare module 'fastify' {
  interface Session {
    grant: GrantSession
    user: unknown
  }
}

export type UserInfo = {
  email_verified: boolean
  name: string
  preferred_username: string
  given_name: string
  family_name: string
}

export type KeycloakOptions = {
  appOrigin: string
  keycloakSubdomain: string
  clientId: string
  clientSecret: string
  useHttps?: boolean
  logoutEndpoint?: string
  excludedPatterns?: Array<string>
  scope?: Array<string>
  userPayloadMapper?: (userPayload: UserInfo) => {}
}

export default fastifyPlugin(async (fastify: FastifyInstance, opts: KeycloakOptions) => {
  const protocol = opts.useHttps ? 'https://' : 'http://'

  const keycloakUrl = `${protocol}${opts.keycloakSubdomain}`

  const grantUrl = `${opts.appOrigin}/connect/keycloak`

  const issuer = await Issuer.discover(keycloakUrl)

  const client = new issuer.Client({
    client_id: opts.clientId,
    client_secret: opts.clientSecret
  })

  fastify.register(cookie)

  fastify.register(session, {
    secret: new Array(32).fill('a').join(''),
    cookie: { secure: false }
  })

  fastify.register(
    grant.fastify()({
      defaults: {
        origin: opts.appOrigin,
        transport: 'session'
      },
      keycloak: {
        key: opts.clientId,
        secret: opts.clientSecret,
        oauth: 2,
        authorize_url: issuer.metadata.authorization_endpoint,
        access_url: issuer.metadata.token_endpoint,
        callback: '/',
        scope: opts.scope ?? ['openid'],
        nonce: true
      }
    })
  )

  function getGrantFromSession(request: FastifyRequest): E.Either<Error, GrantSession> {
    return pipe(
      request.session.grant,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`grant not found in session`)),
        () => E.right(request.session.grant)
      )
    )
  }

  function getResponseFromGrant(grant: GrantSession): E.Either<Error, GrantResponse> {
    return pipe(
      grant.response,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`response not found in grant`)),
        (response) => E.right(response)
      )
    )
  }

  function getIdtokenFromResponse(response: GrantResponse): E.Either<Error, string> {
    return pipe(
      response.id_token,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`id_token not found in response with response: ${response}`)),
        (id_token) => E.right(id_token)
      )
    )
  }

  function introspect(token: string) {
    return TE.tryCatch(
      () => client.introspect(token),
      (error) => new Error(`Failed to introspect token: ${error}`)
    )
  }

  function authentication(request: FastifyRequest): TE.TaskEither<Error, IntrospectionResponse> {
    return pipe(
      getGrantFromSession(request),
      E.chain(getResponseFromGrant),
      E.chain(getIdtokenFromResponse),
      TE.fromEither,
      TE.chain(introspect)
    )
  }

  function getBearerTokenFromRequest(request: FastifyRequest): O.Option<string> {
    return pipe(
      request.headers.authorization,
      O.fromNullable,
      O.map((str) => str.substring(7))
    )
  }

  const grantRoutes = ['/connect/:provider', '/connect/:provider/:override']

  function isGrantRoute(request: FastifyRequest): boolean {
    return grantRoutes.includes(request.routerPath)
  }

  const userPayloadMapper = pipe(
    opts.userPayloadMapper,
    O.fromNullable,
    O.match(
      () => (userPayload: UserInfo) => ({
        account: userPayload.preferred_username,
        name: userPayload.name
      }),
      (a) => a
    )
  )

  function authenticationByGrant(request: FastifyRequest, reply: FastifyReply) {
    return pipe(
      authentication(request),
      TE.match(
        (e) => {
          request.log.debug(`${e}`)
          reply.redirect(grantUrl)
        },
        (response) => {
          if (response.active) {
            request.session.user = userPayloadMapper(response as any)
            request.log.debug(`${inspect(request.session.user, false, null)}`)
          } else {
            reply.redirect(grantUrl)
          }
        }
      )
    )
  }

  function authenticationByToken(request: FastifyRequest, reply: FastifyReply, bearerToken: string) {
    return pipe(
      bearerToken,
      introspect,
      TE.match(
        (error) => {
          request.log.debug(`${error}`)
          reply.status(500).send({ error })
        },
        (response) => {
          if (response.active) {
            request.session.user = userPayloadMapper(response as any)
            request.log.debug(`${inspect(request.session.user, false, null)}`)
          } else {
            reply.status(401).send(`Unauthorized`)
          }
        }
      )
    )
  }

  const matchers = pipe(
    opts.excludedPatterns?.map((pattern) => wcmatch(pattern)),
    O.fromNullable
  )

  function filterExcludedPattern(request: FastifyRequest) {
    return pipe(
      matchers,
      O.map((matchers) => matchers.filter((matcher) => matcher(request.url))),
      O.map((matchers) => matchers.length > 0),
      O.match(
        () => O.of(request),
        (b) =>
          pipe(
            b,
            B.match(
              () => O.of(request),
              () => O.none
            )
          )
      )
    )
  }

  function filterGrantRoute(request: FastifyRequest) {
    return pipe(
      request,
      O.fromPredicate((request) => !isGrantRoute(request))
    )
  }

  fastify.addHook('preValidation', (request: FastifyRequest, reply: FastifyReply, done) => {
    pipe(
      request,
      filterGrantRoute,
      O.chain(filterExcludedPattern),
      O.match(
        () => {
          done()
        },
        (request) => {
          pipe(
            request,
            getBearerTokenFromRequest,
            O.match(
              () => authenticationByGrant(request, reply),
              (bearerToken) => authenticationByToken(request, reply, bearerToken)
            )
          )().then(() => done())
        }
      )
    )
  })

  function logout(request: FastifyRequest, reply: FastifyReply) {
    request.session.destroy((error) => {
      pipe(
        error,
        O.fromNullable,
        O.match(
          () => {
            reply.redirect(`${issuer.metadata.end_session_endpoint}?redirect_uri=${opts.appOrigin}`)
          },
          (e) => {
            request.log.error(`Failed to logout: ${e}`)
            reply.status(500).send({ msg: `Internal Server Error: ${e}` })
          }
        )
      )
    })
  }

  const logoutEndpoint = opts.logoutEndpoint ?? '/logout'

  fastify.get(logoutEndpoint, async (request, reply) => {
    pipe(
      request.session.user,
      O.fromNullable,
      O.match(
        () => {
          reply.redirect('/')
        },
        () => {
          logout(request, reply)
        }
      )
    )
  })

  fastify.log.info(`Keycloak registered successfully!`)
  return fastify
})
