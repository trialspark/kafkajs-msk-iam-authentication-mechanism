import * as uuid from 'uuid';
import {
  fromNodeProviderChain,
  fromTemporaryCredentials,
} from '@aws-sdk/credential-providers';
import { SignatureV4 } from '@aws-sdk/signature-v4';
import { type AwsCredentialIdentity, type Provider } from '@aws-sdk/types';
import { createHash } from 'crypto';

import { Sha256HashConstructor } from './Sha256Constructor';

const service = 'kafka-cluster';
const signedHeaders = 'host';
const hashedPayload =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const algorithm = 'AWS4-HMAC-SHA256';
const action = 'kafka-cluster:Connect';

export type AuthenticationPayloadCreatorOptions = {
  /** A uuid that is shared for this instance of the KafkaJS client. */
  id: string;

  /** The AWS region of the Kafka broker. */
  region: string;

  /** The host of the broker being connected to */
  brokerHost: string;

  /**
   * Provides the time period, in seconds, for which the generated presigned URL is valid.
   * Defaults to 900 seconds.
   */
  ttl?: string;

  /** A string that describes the client. */
  userAgent?: string;

  /**
   * The ARN of a role to assume. If specified, temporary credentials for the role will
   * be used.
   */
  assumeRole?: string;
};

export type AuthenticationPayload = {
  version: '2020_10_22';
  'user-agent': string;
  host: string;
  action: typeof action;
  'x-amz-credential': string;
  'x-amz-algorithm': typeof algorithm;
  'x-amz-date': string;
  'x-amz-security-token': string | undefined;
  'x-amz-signedheaders': typeof signedHeaders;
  'x-amz-expires': string;
  'x-amz-signature': string;
};

type PermanentAuthenticationData = {
  expires: false;
  expiration: undefined;
  expiresIn: undefined;
  payload: AuthenticationPayload;
};

type TemporaryAuthenticationData = {
  expires: true;
  expiration: Date;
  /** The number of milliseconds the credentials will expire in. */
  expiresIn: number;
  payload: AuthenticationPayload;
};

type AuthenticationData =
  | PermanentAuthenticationData
  | TemporaryAuthenticationData;

export class AuthenticationPayloadCreator {
  private readonly id: string;
  private readonly brokerHost: string;
  private readonly region: string;
  private readonly ttl: string;
  private readonly userAgent: string;
  private readonly provider: Provider<AwsCredentialIdentity>;
  private readonly signature: SignatureV4;

  constructor({
    id,
    brokerHost,
    region,
    ttl,
    userAgent,
    assumeRole,
  }: AuthenticationPayloadCreatorOptions) {
    this.id = uuid.v5(brokerHost, id);
    this.brokerHost = brokerHost;
    this.region = region;
    this.ttl = ttl ?? '900';
    this.userAgent = userAgent ?? 'MSK_IAM_v1.0.0';
    this.provider = (() => {
      let cachedCredentials: Promise<AwsCredentialIdentity> | undefined;

      return async () => {
        cachedCredentials ??= (
          assumeRole
            ? fromTemporaryCredentials({
                params: {
                  // eslint-disable-next-line @typescript-eslint/naming-convention
                  RoleArn: assumeRole,
                  // eslint-disable-next-line @typescript-eslint/naming-convention
                  RoleSessionName: `aws-sdk-js-kafkajs-${this.id}`,
                },
              })
            : fromNodeProviderChain()
        )();

        return cachedCredentials;
      };
    })();

    this.signature = new SignatureV4({
      credentials: this.provider,
      region: this.region,
      service,
      applyChecksum: false,
      uriEscapePath: true,
      sha256: Sha256HashConstructor,
    });
  }

  // TESTED
  async create(): Promise<AuthenticationData> {
    const { accessKeyId, sessionToken, expiration } = await this.provider();

    const now = Date.now();

    const xAmzCredential = this.generateXAmzCredential(
      accessKeyId,
      this.timestampYYYYmmDDFormat(now),
    );
    const canonicalHeaders = this.generateCanonicalHeaders(this.brokerHost);
    const canonicalQueryString = this.generateCanonicalQueryString(
      this.timestampYYYYmmDDTHHMMSSZFormat(now),
      xAmzCredential,
      sessionToken,
    );
    const canonicalRequest = this.generateCanonicalRequest(
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      hashedPayload,
    ); //
    const stringToSign = this.generateStringToSign(now, canonicalRequest);

    const signature = await this.signature.sign(stringToSign, {
      signingDate: new Date(now).toISOString(),
    });

    const payload: AuthenticationPayload = {
      version: '2020_10_22',
      'user-agent': this.userAgent,
      host: this.brokerHost,
      action,
      'x-amz-credential': xAmzCredential,
      'x-amz-algorithm': algorithm,
      'x-amz-date': this.timestampYYYYmmDDTHHMMSSZFormat(now),
      'x-amz-security-token': sessionToken,
      'x-amz-signedheaders': signedHeaders,
      'x-amz-expires': this.ttl,
      'x-amz-signature': signature,
    };

    if (!expiration) {
      return {
        expires: false,
        expiration: undefined,
        expiresIn: undefined,
        payload,
      };
    }

    return {
      expires: true,
      expiration,
      expiresIn: expiration.valueOf() - now,
      payload,
    };
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  private timestampYYYYmmDDFormat(date: number) {
    return this.timestampYYYYmmDDTHHMMSSZFormat(date).substring(0, 8);
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  private timestampYYYYmmDDTHHMMSSZFormat(date: number) {
    const d = new Date(date);
    return d.toISOString().replace(/[-.:]/g, '').substring(0, 15).concat('Z');
  }

  private generateCanonicalHeaders(brokerHost: string) {
    return `host:${brokerHost}\n`;
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  private generateXAmzCredential(accessKeyId: string, dateString: string) {
    return `${accessKeyId}/${dateString}/${this.region}/${service}/aws4_request`;
  }

  private generateStringToSign(date: number, canonicalRequest: string) {
    return `${algorithm}
${this.timestampYYYYmmDDTHHMMSSZFormat(date)}
${this.timestampYYYYmmDDFormat(date)}/${this.region}/${service}/aws4_request
${createHash('sha256').update(canonicalRequest, 'utf8').digest('hex')}`;
  }

  private generateCanonicalQueryString(
    dateString: string,
    xAmzCredential: string,
    sessionToken: string | undefined,
  ) {
    let canonicalQueryString = '';
    canonicalQueryString += `${encodeURIComponent(
      'Action',
    )}=${encodeURIComponent(action)}&`;
    canonicalQueryString += `${encodeURIComponent(
      'X-Amz-Algorithm',
    )}=${encodeURIComponent(algorithm)}&`;
    canonicalQueryString += `${encodeURIComponent(
      'X-Amz-Credential',
    )}=${encodeURIComponent(xAmzCredential)}&`;
    canonicalQueryString += `${encodeURIComponent(
      'X-Amz-Date',
    )}=${encodeURIComponent(dateString)}&`;
    canonicalQueryString += `${encodeURIComponent(
      'X-Amz-Expires',
    )}=${encodeURIComponent(this.ttl)}&`;

    if (sessionToken)
      canonicalQueryString += `${encodeURIComponent(
        'X-Amz-Security-Token',
      )}=${encodeURIComponent(sessionToken)}&`;

    canonicalQueryString += `${encodeURIComponent(
      'X-Amz-SignedHeaders',
    )}=${encodeURIComponent(signedHeaders)}`;

    return canonicalQueryString;
  }

  private generateCanonicalRequest(
    canonicalQueryString: string,
    canonicalHeaders: string,
    signedHeaders: string,
    hashedPayload: string,
  ) {
    return (
      'GET\n' +
      '/\n' +
      canonicalQueryString +
      '\n' +
      canonicalHeaders +
      '\n' +
      signedHeaders +
      '\n' +
      hashedPayload
    );
  }
}
