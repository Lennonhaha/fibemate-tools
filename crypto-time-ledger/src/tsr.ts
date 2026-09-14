/**
 * TSR (RFC 3161 timestamp) verification glue.
 *
 * This module uses the `pkijs` library to parse the CMS SignedData structure and
 * cryptographically verify the signature. `pkijs` delegates the actual crypto to
 * Node's native WebCrypto (`crypto.webcrypto`) — we do NOT implement ASN.1/CMS
 * parsing or signature math ourselves (hand-rolling that is a known high-risk area).
 *
 * The only logic added on top of `pkijs`:
 *   1. A pinned-certificate allowlist. v1 requires a non-empty trust-anchor set;
 *      an empty set fails closed (returns false). Pinning is done by comparing the
 *      SINGLE signer certificate's public-key (SPKI) DER — as resolved by pkijs from
 *      the SignerInfo — against each pinned cert's SPKI DER. This is stricter than
 *      matching any certificate in the SignedData (PKI-1).
 *   2. An explicit messageImprint check: the TSTInfo's `hashedMessage` MUST equal
 *      the digest we are verifying. `SignedData.verify()` does NOT perform this
 *      semantic check — it only validates the cryptographic signature.
 *   3. A temporary eContentType override. pkijs's `SignedData.verify()` auto-detects
 *      `eContentType === TSTInfo` and then insists on re-deriving the messageImprint
 *      from the *original data* (the `data` param). Our contract only has the digest,
 *      never the original data, so that branch is unusable for us. We override
 *      `eContentType` to `id-data` so pkijs performs a plain CMS signature
 *      verification over the embedded TSTInfo DER — exactly what we need. The override
 *      is on the in-memory parse only; the `.tsr` file is never mutated.
 *
 * NOTE: genTime consistency (the TSR's genTime vs the block's `ts`) is NOT checked
 * here. The `VerifyTSR` contract only receives `digest`; cross-checking genTime
 * requires the block, which the CLI layer holds. The CLI MUST perform that check.
 */

import { webcrypto } from "node:crypto";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { fromBER } from "asn1js";
import {
  ContentInfo,
  CryptoEngine,
  SignedData,
  TSTInfo,
  TimeStampResp,
  setEngine,
} from "pkijs";

setEngine("node", new CryptoEngine({ crypto: webcrypto as any }));

export interface TSRVerifyOptions {
  tsrDir: string;
  pinnedTsaCerts?: string[];
}

export type VerifyTSR = (digest: string) => Promise<boolean>;

function spkiDerOfPem(pem: string): Buffer {
  return new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
}

export function makeVerifyTSR(opts: TSRVerifyOptions): VerifyTSR {
  const dir = opts.tsrDir;
  const pinned = opts.pinnedTsaCerts ?? [];
  const pinnedSpki = pinned.map(spkiDerOfPem);

  return async (digest: string): Promise<boolean> => {
    if (!digest) return false;
    const hex = digest.startsWith("sha256:") ? digest.slice(7) : digest;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) return false;
    if (pinnedSpki.length === 0) return false; // v1 requires a trust anchor; fail closed

    const file = `${dir}/${hex}.tsr`;
    let der: Buffer;
    try {
      der = readFileSync(file);
    } catch {
      return false; // missing .tsr -> false, never throw
    }

    try {
      const tsr = new TimeStampResp({ schema: fromBER(der).result });
      const ci = tsr.timeStampToken;
      if (!ci) return false;
      const sd = new SignedData({ schema: ci.content });

      // See docstring point 3: override eContentType so pkijs skips its TSTInfo
      // "needs original data" branch and just verifies the CMS signature.
      sd.encapContentInfo.eContentType = "1.2.840.113549.1.7.1"; // id-data
      const vres = await sd.verify({ signer: 0, extendedMode: true });
      if (!vres.signatureVerified) return false;

      // Pinned-cert allowlist: the SINGLE signer certificate resolved by pkijs must
      // match a pinned certificate by public key (SPKI) DER (PKI-1).
      if (!vres.signerCertificate) return false;
      const signerSpki = new X509Certificate(
        Buffer.from(vres.signerCertificate.toSchema().toBER()),
      ).publicKey.export({ type: "spki", format: "der" });
      if (!pinnedSpki.some((p) => p.equals(signerSpki))) return false;

      // Explicit messageImprint check (not done by SignedData.verify()).
      const eContent = sd.encapContentInfo.eContent;
      if (!eContent) return false;
      const tstInfo = new TSTInfo({ schema: fromBER(eContent.valueBlock.valueHexView).result });
      const gotHex = Buffer.from(
        tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView,
      ).toString("hex");
      if (gotHex !== hex) return false;

      return true;
    } catch {
      return false; // corrupt / not RFC3161 -> false
    }
  };
}
