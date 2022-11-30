import * as uuid from 'uuid';
import type { Mechanism, SaslAuthenticationResponse } from 'kafkajs';

import {
  type AuthenticationPayload,
  AuthenticationPayloadCreator,
  type AuthenticationPayloadCreatorOptions,
} from './AuthenticationPayloadCreator';

export type AwsIamAuthenticatorOptions = Pick<
  AuthenticationPayloadCreatorOptions,
  'region' | 'ttl' | 'assumeRole'
>;

const int32Size = 4;

const request = (payload: AuthenticationPayload) => ({
  encode() {
    const stringifiedPayload = JSON.stringify(payload);
    const byteLength = Buffer.byteLength(stringifiedPayload, 'utf8');
    const buf = Buffer.alloc(int32Size + byteLength);
    buf.writeUInt32BE(byteLength, 0);
    buf.write(stringifiedPayload, int32Size, byteLength, 'utf8');
    return buf;
  },
});

const response: SaslAuthenticationResponse<{ version?: string }> = {
  decode(rawData: Buffer) {
    const byteLength = rawData.readInt32BE(0);
    return rawData.slice(int32Size, int32Size + byteLength);
  },

  parse(data: Buffer) {
    return JSON.parse(data.toString()) as Record<string, unknown>;
  },
};

export const awsIamAuthenticator = (
  options: AwsIamAuthenticatorOptions,
): Mechanism['authenticationProvider'] => {
  const id = uuid.v4();

  return ({ host, port, logger, saslAuthenticate }) => ({
    async authenticate() {
      const broker = `${host}:${port}`;
      const payloadFactory = new AuthenticationPayloadCreator({
        ...options,
        id,
        brokerHost: host,
      });

      try {
        const auth = await payloadFactory.create();
        const authenticateResponse = await saslAuthenticate({
          request: request(auth.payload),
          response,
        });
        logger.info('Authentication response', { authenticateResponse });

        if (!authenticateResponse?.version) {
          throw new Error('Invalid response from broker');
        }

        logger.info('SASL Simon authentication successful', { broker });
      } catch (error) {
        if (error instanceof Error) {
          logger.error(error.message, { broker });
        }

        throw error;
      }
    },
  });
};
