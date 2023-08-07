import { generateKeyPairSync } from "crypto";
import { sign, verify } from "./auth";
import { add, sub } from "date-fns";

const KEY_PAIR_TYPE = "rsa";

const generateKeyPair = (): { publicKey: string; privateKey: string } =>
  generateKeyPairSync(KEY_PAIR_TYPE, {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

const keyPair = generateKeyPair();

console.log("keyPair", keyPair);

// Gerando uma assinatura usando a chave privada no lado do cliente 👇

const now = new Date();
// URI do recurso da API
const uri = "/api/v1/payment/1";
// Corpo da requisição HTTP
const body = { foo: "bar" };

const signature = sign({
  uri,
  body,
  // Data quando o token foi gerado.
  iat: now,
  // Data quando o token deve expirar.
  exp: add(now, { seconds: 30 }),
  privateKey: Buffer.from(keyPair.privateKey, "utf8"),
});

console.log("Signature", signature);

// Validando a assinatura com a chave pública no lado do serviço 👇

console.log(
  "Valid: ",
  verify({
    publicKey: keyPair.publicKey,
    signature,
    body,
    uri,
  })
);

console.log(
  "Invalid: Body mismatch",
  verify({
    publicKey: keyPair.publicKey,
    signature,
    // Exemplo de tampering: o corpo da requisição foi alterado mas a assinatura
    // segue a mesma.
    body: { tamperedBody: "Give me your money 😈 muhahaha" },
    uri,
  })
);

console.log(
  "Invalid: URI mismatch",
  verify({
    publicKey: keyPair.publicKey,
    signature,
    body,
    // Exemplo de tampering: a URI foi alterada mas a assinatura segue a mesma.
    uri: "/api/v1/payment/42",
  })
);

console.log(
  "Invalid: Mismatch key pair",
  verify({
    publicKey: generateKeyPair().publicKey,
    signature,
    body,
    uri,
  })
);

const pastIssueDate = sub(now, { minutes: 1 });

console.log(
  "Invalid: Expired token",
  verify({
    body,
    uri,
    publicKey: keyPair.publicKey,
    signature: sign({
      uri,
      body,
      iat: pastIssueDate,
      exp: add(pastIssueDate, { seconds: 30 }),
      privateKey: Buffer.from(keyPair.privateKey, "utf8"),
    }),
  })
);
