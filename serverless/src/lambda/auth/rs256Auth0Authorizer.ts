import { CustomAuthorizerEvent, CustomAuthorizerResult, CustomAuthorizerHandler } from 'aws-lambda'
import 'source-map-support/register'
import * as middy from 'middy'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'
// import { Client } from 'elasticsearch'


const cert =`
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJUqpdHGD8nVJ/MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi13dzc0emo0YS5hdXRoMC5jb20wHhcNMjAwMjAzMjE1MjE3WhcNMzMx
MDEyMjE1MjE3WjAhMR8wHQYDVQQDExZkZXYtd3c3NHpqNGEuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06vGAsIU1TJc9i2ye4/sAtqJ
NqqntJZ5QokmT0T+RgetNK4k3lz+A9Xxgx/vDLeTzRxvn6AWMHFNhCZZ09XnfWZ5
WkyZvNHVd7SPdNvsEWfpbQWH4G+iXjdx8NBCX/faWNJBVKocRHnAEVyCJ4KUt55Z
z0YpTXtALjEN5EA8fFuVMDL7EpSjzqcO87JoMc6XX6T8RbLtA8fP5dT7D8QHLH7P
7+TfooEH43Mj0plpVFo56RcREqEIkuMLt5aQ2blDXSZzlOGBB9mF8/vxww+kig9T
I1AWTyMYLWW3fnspPIQwoOgO4a0acowA0tnCIvs3Eu6afKNaqWf3bp7RsVWNFwID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ12VghkdfaMqYYFZc0
kmBJ7PG1PTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAJsrgeAZ
3X6vjOIR3Hzr3qTXGW079XfO/z5uuBeZyPE6PiwvbbHhgK8z49jBE9STfsCz6R/T
SsiRjB4vWkPS+E/f20cbctIVcUZjRnvdH+i8t69xATLMySLZ2q5f39SVWKRk0i8e
z8qQTfq2fq2qBCuaLfblRpdRXDmLE24IjyhzOesROieWjtZjctxwSedRgiv+wrAp
E+bnvCuNPK//JuNHEMDdVA/JTwwElOBpR8DcmXy1WctdDW4BimWBitW/ylf5ou37
G5eo9O4pM16mhENiW/7sg3H7asRsxKquzP4YtcVgum2jybND1wQ4ioIuPd8DV6kB
MAxxarbxDG6i0y0=
-----END CERTIFICATE-----
`

// const secretField = process.env.AUTH_0_SECRET_FIELD

export const handler = middy(async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const decodedToken = verifyToken(
      event.authorizationToken,
    )
    console.log('User was authorized', decodedToken)

    return {
      principalId: decodedToken.sub,
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
    console.log('User was not authorized', e.message)

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
})

function verifyToken(authHeader: string): JwtToken{
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]


  return verify(token, cert, {algorithms:['RS256']}) as JwtToken
}



