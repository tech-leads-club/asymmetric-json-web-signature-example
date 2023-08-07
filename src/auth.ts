import { createHash } from "crypto";
import jws from "jws";
import { add, getUnixTime, fromUnixTime } from "date-fns";

// Algoritmo de assinatura assimétrica.
export const CRYPTOGRAPHIC_ALGORITHM = "RS256";

const INVALID_SIGNATURE = "Invalid signature";
const SIGNATURE_HAS_EXPIRED = "Signature has expired";
const INVALID_JWT_PAYLOAD = "Invalid JWT payload";
const MISMATCH_URI = "Mismatch signed URI";
const MISMATCH_BODY_HASH = "Mismatch signed body hash";
const MISMATCH_KEY_PAIR = "Mismatch key pair";
const UNVERIFIED_SIGNATURE = "Unverified signature";

export const hash = (obj: Record<string, unknown>): string =>
  createHash("sha256").update(JSON.stringify(obj)).digest("base64");

export const sign = (options: {
  body: any;
  privateKey: Buffer;
  iat: Date;
  uri: string;
  exp?: Date;
}): string => {
  const { body, privateKey, iat, uri } = options;
  const exp = options.exp ? options.exp : add(iat, { minutes: 1 });

  return jws.sign({
    header: {
      alg: CRYPTOGRAPHIC_ALGORITHM,
    },
    payload: {
      uri,
      iat: getUnixTime(iat),
      exp: getUnixTime(exp),
      bodyHash: hash(body),
    },
    privateKey,
  });
};

type Success = {
  success: true;
};

type Failure = {
  success: false;
  error: {
    message: string;
  };
};

const failure = (message: string): Failure => ({
  success: false,
  error: { message },
});

export const verify = ({
  publicKey,
  signature,
  body,
  uri,
  now = new Date(),
}: {
  publicKey: string;
  signature: string;
  body: Record<string, unknown>;
  uri: string;
  now?: Date;
}): Failure | Success => {
  const isValid = jws.isValid(signature);

  if (!isValid) {
    return failure(INVALID_SIGNATURE);
  }

  const decodedSignature = jws.decode(signature);
  // 💡 Dica: Uso do Zod para validar o payload do JWT.
  const payload = JSON.parse(decodedSignature.payload);

  // 🚨 É extremamente importante para a segurança que o algoritmo de assinatura
  // seja validado.
  //
  // Como o JWT é gerado pelo cliente, um atacante pode gerar um JWT com um
  // algoritmo HS256 que é simétrico. Consequentemente, o serviço usará a chave
  // pública para validar a assinatura que resultará em uma validação de
  // sucesso.
  //
  // Veja também:
  // - CVE-2015-9235
  // - https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#modify-the-algorithm-to-none-cve-2015-9235
  if (decodedSignature.header.alg !== CRYPTOGRAPHIC_ALGORITHM) {
    return failure(INVALID_JWT_PAYLOAD);
  }

  if (fromUnixTime(payload.exp) < now) {
    return failure(SIGNATURE_HAS_EXPIRED);
  }

  if (payload.uri !== uri) {
    return failure(MISMATCH_URI);
  }

  if (payload.bodyHash !== hash(body)) {
    return failure(MISMATCH_BODY_HASH);
  }

  try {
    const isVerified = jws.verify(
      signature,
      CRYPTOGRAPHIC_ALGORITHM,
      publicKey
    );

    if (!isVerified) {
      return failure(MISMATCH_KEY_PAIR);
    }
  } catch (error: unknown) {
    return failure(UNVERIFIED_SIGNATURE);
  }

  return {
    success: true,
  };
};
