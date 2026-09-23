/**
 * browser-entry.ts — browser port of the TSR (RFC 3161) verification path.
 *
 * This is the cryptographic core that the demo page currently delegates to the
 * server-side CLI. By shipping it as a single IIFE bundle, a third party can open
 * the page, click "verify", and the signature check runs LOCALLY in their browser
 * via WebCrypto — no trust in the FIBEMATE server required.
 *
 * Mirrors src/tsr.ts (Node) exactly, with two differences:
 *   1. No `node:crypto` X509Certificate — we extract SPKI DER via pkijs Certificate.
 *   2. No manual `setEngine` — pkijs auto-selects its "browser" engine on
 *      `globalThis.crypto` when running in a browser.
 *
 * Security contract (unchanged from tsr.ts):
 *   - Pinned-certificate allowlist by SPKI DER (fail closed on empty set).
 *   - Explicit messageImprint check (SignedData.verify() does NOT do this).
 *   - eContentType override to id-data (skip pkijs "needs original data" branch).
 */

import { fromBER } from "asn1js";
import { Certificate, SignedData, TSTInfo, TimeStampResp } from "pkijs";

// ---- small byte helpers (browser-safe, no Buffer) ----

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---- PEM -> pkijs Certificate -> SPKI DER ----

function pemToCertificate(pem: string): Certificate {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const der = base64ToBytes(b64);
  const asn1 = fromBER(der.buffer as ArrayBuffer);
  return new Certificate({ schema: asn1.result });
}

function spkiDerOfCert(cert: Certificate): Uint8Array {
  return new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER() as ArrayBuffer);
}

/**
 * Split a PEM bundle (possibly multiple certs) into an array of single-cert PEMs.
 */
export function parsePemCerts(pem: string): string[] {
  return pem
    .split(/-----END CERTIFICATE-----/)
    .filter((s) => s.includes("BEGIN CERTIFICATE"))
    .map((s) => `${s}-----END CERTIFICATE-----`);
}

/**
 * Verify an RFC 3161 timestamp token.
 *
 * @param derBytes   Raw DER bytes of the `.tsr` (TimeStampResp) file.
 * @param digestHex  64-char lowercase hex of the messageImprint digest.
 * @param pinnedPem  PEM bundle of trusted TSA certificates (allowlist).
 * @returns          true iff signature verifies AND signer SPKI matches a pinned
 *                   cert AND the embedded messageImprint equals digestHex.
 */
export async function verifyTsrBytes(
  derBytes: Uint8Array,
  digestHex: string,
  pinnedPem: string,
): Promise<boolean> {
  if (!digestHex) return false;
  const hex = digestHex.startsWith("sha256:") ? digestHex.slice(7) : digestHex;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return false;

  const pinnedSpki = parsePemCerts(pinnedPem).map((p) => spkiDerOfCert(pemToCertificate(p)));
  if (pinnedSpki.length === 0) return false; // v1 requires a trust anchor; fail closed

  try {
    const tsr = new TimeStampResp({ schema: fromBER(derBytes.buffer as ArrayBuffer).result });
    const ci = tsr.timeStampToken;
    if (!ci) return false;
    const sd = new SignedData({ schema: ci.content });

    // id-data override: pkijs then does a plain CMS signature verify over the
    // embedded TSTInfo DER instead of trying to re-derive the imprint from data.
    sd.encapContentInfo.eContentType = "1.2.840.113549.1.7.1";
    const vres = await sd.verify({ signer: 0, extendedMode: true });
    if (!vres.signatureVerified) return false;

    // Pinned-cert allowlist (SPKI DER) — same as tsr.ts PKI-1 check.
    if (!vres.signerCertificate) return false;
    const signerSpki = spkiDerOfCert(vres.signerCertificate);
    if (!pinnedSpki.some((p) => bytesEqual(p, signerSpki))) return false;

    // Explicit messageImprint check.
    const eContent = sd.encapContentInfo.eContent;
    if (!eContent) return false;
    const tstInfo = new TSTInfo({ schema: fromBER(eContent.valueBlock.valueHexView).result });
    const gotHex = bytesToHex(
      new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView),
    );
    if (gotHex.toLowerCase() !== hex.toLowerCase()) return false;

    return true;
  } catch {
    return false; // corrupt / not RFC3161 -> false, never throw
  }
}
