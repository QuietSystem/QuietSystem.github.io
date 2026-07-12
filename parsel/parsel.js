/*
 * ============================================================================
 * ENVELOPE — a stateless, client-side secret-sharing utility
 * ============================================================================
 *
 * WHAT THIS IS
 * This page lets you encrypt a piece of text in your own browser and share
 * the encrypted result (as a link, a QR code, a file, or a copy-pasted
 * blob) with someone else, who decrypts it in their own browser with a
 * password you give them separately.
 *
 * There is no server component. Nothing is uploaded anywhere. The page
 * makes zero network requests after it has loaded. Everything you see —
 * encryption, decryption, QR generation — happens locally, in this tab.
 *
 * SECURITY MODEL
 * This is a *transport confidentiality* tool, not a secrets vault. It
 * assumes the channel carrying the encrypted package (email, chat, a
 * pastebin, a USB stick) is not itself trustworthy, and that you will
 * send the password to the recipient through a *different* channel than
 * the one carrying the package (e.g. package by email, password by phone).
 *
 * It protects against:
 *   - anyone who intercepts the encrypted package but not the password
 *   - a server or network operator ever seeing the plaintext (there is no
 *     server, and URL fragments — the part after "#" — are never sent to
 *     web servers by the browser; see buildShareUrl() below)
 *
 * It does NOT protect against:
 *   - a weak or guessed password — encryption strength is bounded by
 *     password strength, not just algorithm strength
 *   - a compromised device, browser, or malicious extension on either end
 *   - someone who obtains both the package and the password
 *
 * CRYPTOGRAPHY
 *   Cipher:      AES-256-GCM (authenticated encryption — tampering with
 *                the package causes decryption to fail loudly rather than
 *                silently returning corrupted data)
 *   IV:          96-bit, freshly random per encryption via
 *                crypto.getRandomValues()
 *   KDF:         PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random
 *                salt. Argon2id would be preferable for its memory-hardness,
 *                but it is not available in the native Web Crypto API.
 *                Adding it would require either a WASM build or a
 *                hand-rolled JS implementation — both conflict with this
 *                project's goal of using only audited, native primitives
 *                with zero external dependencies. PBKDF2 at a high
 *                iteration count is the standard native alternative.
 *   Package:     a small JSON object (version, KDF params, salt, IV,
 *                ciphertext) encoded as Base64URL text. All four sharing
 *                methods (URL, QR, file, clipboard) carry this exact same
 *                string — there is only one artifact, just different ways
 *                to move it around.
 *
 * No compression is applied to the secret before encryption. Compressing
 * attacker-influenced or partially-known plaintext before encrypting it
 * can leak information through the resulting ciphertext's size (this is
 * the same class of issue as the CRIME/BREACH attacks against TLS
 * compression). Skipping compression is a deliberate security choice,
 * not an oversight.
 *
 * MEMORY HANDLING
 * JavaScript cannot guarantee secure memory erasure — the garbage
 * collector may retain copies of strings or typed arrays after they are
 * dereferenced, and this page cannot prevent that. Where practical, this
 * code overwrites typed arrays holding key material and best-effort
 * clears sensitive strings and DOM fields after use, but this is a
 * mitigation, not a guarantee. Close the tab when you're done for the
 * strongest reset.
 *
 * THIRD-PARTY CODE
 * The QR code generator (see the "QR Code" section below) is a compact,
 * from-scratch implementation of the public ISO/IEC 18004 QR algorithm,
 * following the structure of the well-known public-domain "qrcode-
 * generator" approach. It is vendored directly into this file — no CDN,
 * no build step — and is clearly separated from the application logic so
 * it's obvious what's hand-written for this app versus a standard
 * algorithm implementation. It intentionally supports a bounded range of
 * QR versions (1–20); very large secrets will skip the QR code and fall
 * back to the URL, file, and clipboard options, which have no size limit
 * imposed by this app.
 * ============================================================================
 */

(() => {
  'use strict';

  // ==========================================================================
  // Configuration
  // ==========================================================================
  const CONFIG = {
    PACKAGE_VERSION: 1,
    KDF_NAME: 'PBKDF2-SHA256',
    KDF_ITERATIONS: 600000,
    SALT_BYTES: 16,
    IV_BYTES: 12,
    QR_EC_LEVEL: 'L',
    QR_MAX_VERSION: 20,
    QR_MODULE_PX: 4,
    QR_QUIET_ZONE: 4,
    HASH_PREFIX: '#s=',
  };

  // ==========================================================================
  // Utilities
  // ==========================================================================
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function bytesToBase64Url(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToBytes(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const binary = atob(s);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function formatBytes(n) {
    if (n < 1024) return n + ' bytes';
    return (n / 1024).toFixed(1) + ' KB';
  }

  function zeroize(typedArray) {
    if (typedArray && typedArray.fill) typedArray.fill(0);
  }

  function downloadBlob(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function announce(message) {
    const region = document.getElementById('liveRegion');
    if (region) region.textContent = message;
  }

  // ==========================================================================
  // Encoding — the encrypted package format
  // ==========================================================================
  // Package shape (before encoding):
  // { v, kdf, iter, salt, iv, ct }  — salt/iv/ct are Base64URL strings.
  // Transport shape: "v1." + Base64URL(UTF8(JSON.stringify(package)))
  // This single string is what goes in the URL fragment, the QR code, the
  // downloaded file, and the copyable text box — identical in every case.

  function serializePackage(pkg) {
    const json = JSON.stringify(pkg);
    const encoded = bytesToBase64Url(textEncoder.encode(json));
    return `v${CONFIG.PACKAGE_VERSION}.${encoded}`;
  }

  function deserializePackage(str) {
    const trimmed = str.trim();
    const dotIndex = trimmed.indexOf('.');
    if (dotIndex === -1) throw new Error('That doesn\u2019t look like an encrypted package.');
    const versionTag = trimmed.slice(0, dotIndex);
    const body = trimmed.slice(dotIndex + 1);
    if (versionTag !== `v${CONFIG.PACKAGE_VERSION}`) {
      throw new Error(`Unsupported package version "${versionTag}".`);
    }
    let json;
    try {
      json = textDecoder.decode(base64UrlToBytes(body));
    } catch (e) {
      throw new Error('The encrypted package is corrupted or incomplete.');
    }
    let pkg;
    try {
      pkg = JSON.parse(json);
    } catch (e) {
      throw new Error('The encrypted package is corrupted or incomplete.');
    }
    if (!pkg.salt || !pkg.iv || !pkg.ct || !pkg.iter) {
      throw new Error('The encrypted package is missing required fields.');
    }
    return pkg;
  }

  function buildShareUrl(packageStr) {
    // The fragment (everything after "#") is never sent in the HTTP request
    // by the browser — it's resolved entirely client-side. A server hosting
    // this page (or any proxy/CDN in front of it) never sees what follows
    // the "#", which is exactly why the whole encrypted package lives there
    // instead of in a query string.
    const url = new URL(window.location.href);
    url.hash = CONFIG.HASH_PREFIX + packageStr;
    return url.toString();
  }

  function extractPackageFromHash() {
    const hash = window.location.hash;
    if (!hash || !hash.startsWith(CONFIG.HASH_PREFIX)) return null;
    return hash.slice(CONFIG.HASH_PREFIX.length);
  }

  // ==========================================================================
  // Cryptography
  // ==========================================================================
  async function deriveKey(password, salt, iterations, usage) {
    const baseKey = await crypto.subtle.importKey(
      'raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      [usage]
    );
  }

  async function encryptSecret(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_BYTES));
    const key = await deriveKey(password, salt, CONFIG.KDF_ITERATIONS, 'encrypt');
    const plaintextBytes = textEncoder.encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
    const pkg = {
      v: CONFIG.PACKAGE_VERSION,
      kdf: CONFIG.KDF_NAME,
      iter: CONFIG.KDF_ITERATIONS,
      salt: bytesToBase64Url(salt),
      iv: bytesToBase64Url(iv),
      ct: bytesToBase64Url(new Uint8Array(ciphertext)),
    };
    zeroize(salt); zeroize(iv); zeroize(plaintextBytes);
    return pkg;
  }

  async function decryptPackage(pkg, password) {
    const salt = base64UrlToBytes(pkg.salt);
    const iv = base64UrlToBytes(pkg.iv);
    const ct = base64UrlToBytes(pkg.ct);
    const key = await deriveKey(password, salt, pkg.iter, 'decrypt');
    let plaintextBuf;
    try {
      plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    } catch (e) {
      // AES-GCM authentication failure — wrong password or tampered/corrupt data.
      // These are indistinguishable by design, so the message stays generic.
      throw new Error('Incorrect password, or this package is corrupted.');
    } finally {
      zeroize(salt); zeroize(iv);
    }
    const plaintext = textDecoder.decode(plaintextBuf);
    return plaintext;
  }

  function estimatePackageSize(plaintextByteLength) {
    // ciphertext = plaintext + 16-byte GCM auth tag
    const ctBytes = plaintextByteLength + 16;
    const b64 = (n) => Math.ceil(n / 3) * 4;
    // rough JSON overhead: field names, punctuation, version/iter numbers
    const jsonOverhead = 95;
    const totalBase64ish = b64(CONFIG.SALT_BYTES) + b64(CONFIG.IV_BYTES) + b64(ctBytes) + jsonOverhead;
    return Math.ceil(totalBase64ish * 4 / 3); // final outer Base64URL layer
  }

  // ==========================================================================
  // Compression
  // ==========================================================================
  // Deliberately not implemented. Compressing plaintext before encryption can
  // leak information about its content through the compressed (and therefore
  // ciphertext) length — the same category of weakness behind CRIME/BREACH.
  // For a tool whose entire purpose is confidentiality, that tradeoff isn't
  // worth a modest size reduction. Secrets are encrypted as raw UTF-8 bytes.

  // ==========================================================================
  // QR Code
  // ==========================================================================
  // A compact, from-scratch implementation of the ISO/IEC 18004 QR encoding
  // algorithm: Galois-field (GF(256)) arithmetic for Reed–Solomon error
  // correction, standard module placement, and a single fixed data mask
  // (pattern 0, i.e. modules are inverted where (row + col) is even). Using
  // a fixed mask rather than evaluating all 8 candidate masks for the
  // "best" one is a deliberate simplification — any of the 8 masks
  // produces a spec-valid, scannable code, it just means the output isn't
  // always the theoretically most-scannable variant. Supports byte-mode
  // encoding for QR versions 1–20 (see CONFIG.QR_MAX_VERSION); larger
  // payloads skip QR generation rather than guess at higher-version tables.
  const QR = (() => {
    const EXP_TABLE = new Array(256);
    const LOG_TABLE = new Array(256);
    for (let i = 0; i < 8; i++) EXP_TABLE[i] = 1 << i;
    for (let i = 8; i < 256; i++) {
      EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
    }
    for (let i = 0; i < 255; i++) LOG_TABLE[EXP_TABLE[i]] = i;
    const glog = (n) => { if (n < 1) throw new Error('glog domain'); return LOG_TABLE[n]; };
    const gexp = (n) => { while (n < 0) n += 255; while (n >= 256) n -= 255; return EXP_TABLE[n]; };

    class Poly {
      constructor(num, shift) {
        let offset = 0;
        while (offset < num.length - 1 && num[offset] === 0) offset++;
        this.num = new Array(num.length - offset + shift).fill(0);
        for (let i = 0; i < num.length - offset; i++) this.num[i] = num[i + offset];
      }
      get(i) { return this.num[i]; }
      get length() { return this.num.length; }
      multiply(e) {
        const num = new Array(this.length + e.length - 1).fill(0);
        for (let i = 0; i < this.length; i++) {
          for (let j = 0; j < e.length; j++) num[i + j] ^= gexp(glog(this.get(i)) + glog(e.get(j)));
        }
        return new Poly(num, 0);
      }
      mod(e) {
        if (this.length - e.length < 0) return this;
        const ratio = glog(this.get(0)) - glog(e.get(0));
        const num = this.num.slice();
        for (let i = 0; i < e.length; i++) num[i] ^= gexp(glog(e.get(i)) + ratio);
        return new Poly(num, 0).mod(e);
      }
    }

    function errorCorrectPoly(n) {
      let a = new Poly([1], 0);
      for (let i = 0; i < n; i++) a = a.multiply(new Poly([1, gexp(i)], 0));
      return a;
    }

    // [blockCount, totalCount, dataCount] groups per version (rows) x EC level
    // (L, M, Q, H columns; some levels split into two groups of different
    // sizes). Versions 1–20 only — see module doc comment above.
    const RS_BLOCK_TABLE = [
      [1,26,19,  1,26,16,  1,26,13,  1,26,9],
      [1,44,34,  1,44,28,  1,44,22,  1,44,16],
      [1,70,55,  1,70,44,  2,35,17,  2,35,13],
      [1,100,80, 2,50,32,  2,50,24,  4,25,9],
      [1,134,108,2,67,43,  2,33,15,2,34,15, 2,33,11,2,34,11],
      [2,86,68,  4,43,27,  4,43,19,  4,43,15],
      [2,98,78,  4,49,31,  2,32,14,4,33,15, 4,39,13,1,40,14],
      [2,121,97, 2,60,38,2,61,39, 4,40,18,2,41,19, 4,40,14,2,41,15],
      [2,146,116,3,58,36,2,59,37, 4,36,16,4,37,17, 4,36,12,4,37,13],
      [2,86,68,2,87,69, 4,69,43,1,70,44, 6,43,19,2,44,20, 6,43,15,2,44,16],
      [4,101,81, 1,80,50,4,81,51, 4,50,22,4,51,23, 3,36,12,8,37,13],
      [2,116,92,2,117,93, 6,58,36,2,59,37, 4,46,20,6,47,21, 7,42,14,4,43,15],
      [4,133,107, 8,59,37,1,60,38, 8,44,20,4,45,21, 12,33,11,4,34,12],
      [3,145,115,1,146,116, 4,64,40,5,65,41, 11,36,16,5,37,17, 11,36,12,5,37,13],
      [5,109,87,1,110,88, 5,65,41,5,66,42, 5,54,24,7,55,25, 11,36,12,7,37,13],
      [5,122,98,1,123,99, 7,73,45,3,74,46, 15,43,19,2,44,20, 3,45,15,13,46,16],
      [1,135,107,5,136,108, 10,74,46,1,75,47, 1,50,22,15,51,23, 2,42,14,17,43,15],
      [5,150,120,1,151,121, 9,69,43,4,70,44, 17,50,22,1,51,23, 2,42,14,19,43,15],
      [3,141,113,4,142,114, 3,70,44,11,71,45, 17,47,21,4,48,22, 9,39,13,16,40,14],
      [3,135,107,5,136,108, 3,67,41,13,68,42, 15,54,24,5,55,25, 15,43,15,10,44,16],
    ];
    const GROUPS_PER_LEVEL = [
      [1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,2,2],
      [1,1,1,1],[1,1,2,2],[1,2,2,2],[1,2,2,2],[2,2,2,2],
      [1,2,2,2],[2,2,2,2],[1,1,2,2],[2,2,2,2],[2,2,2,2],
      [2,2,2,2],[2,2,2,2],[2,2,2,2],[2,2,2,2],[2,2,2,2],
    ];
    const EC_LEVEL_INDEX = { L: 0, M: 1, Q: 2, H: 3 };
    const REMAINDER_BITS = [0,7,7,7,7,7,0,0,0,0,0,0,0,3,3,3,3,3,3,3];
    const ALIGNMENT_POSITIONS = [
      null,[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],
      [6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],
      [6,30,56,82],[6,30,58,86],[6,34,62,86],
    ];

    function rsBlocksFor(version, ecLevel) {
      const row = RS_BLOCK_TABLE[version - 1];
      const groups = GROUPS_PER_LEVEL[version - 1];
      const li = EC_LEVEL_INDEX[ecLevel];
      let idx = 0;
      for (let l = 0; l < li; l++) idx += groups[l] * 3;
      const blocks = [];
      for (let g = 0; g < groups[li]; g++) {
        const count = row[idx], total = row[idx + 1], data = row[idx + 2];
        for (let k = 0; k < count; k++) blocks.push({ totalCount: total, dataCount: data });
        idx += 3;
      }
      return blocks;
    }

    function dataCapacityBytes(version, ecLevel) {
      const totalDataBytes = rsBlocksFor(version, ecLevel).reduce((s, b) => s + b.dataCount, 0);
      const lenBits = version <= 9 ? 8 : 16;
      return Math.floor((totalDataBytes * 8 - (4 + lenBits)) / 8);
    }

    function chooseVersion(byteLength, ecLevel, maxVersion) {
      for (let v = 1; v <= maxVersion; v++) {
        if (dataCapacityBytes(v, ecLevel) >= byteLength) return v;
      }
      return null;
    }

    function encodeDataBits(bytes, version) {
      const lenBits = version <= 9 ? 8 : 16;
      const bits = [];
      const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
      push(0b0100, 4); // byte-mode indicator
      push(bytes.length, lenBits);
      for (const b of bytes) push(b, 8);
      return bits;
    }

    function bitsToDataCodewords(bits, totalNeeded) {
      const maxBits = totalNeeded * 8;
      for (let i = 0; i < 4 && bits.length < maxBits; i++) bits.push(0);
      while (bits.length % 8 !== 0) bits.push(0);
      const bytes = [];
      for (let i = 0; i < bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
        bytes.push(b);
      }
      const PAD0 = 0xEC, PAD1 = 0x11;
      let p = 0;
      while (bytes.length < totalNeeded) bytes.push(p++ % 2 === 0 ? PAD0 : PAD1);
      return bytes;
    }

    function buildCodewords(bytes, version, ecLevel) {
      const blocks = rsBlocksFor(version, ecLevel);
      const totalDataCodewords = blocks.reduce((s, b) => s + b.dataCount, 0);
      const bits = encodeDataBits(bytes, version);
      const dataBytes = bitsToDataCodewords(bits, totalDataCodewords);

      let offset = 0;
      const blockData = [], blockEC = [];
      let maxDc = 0, maxEc = 0;
      for (const blk of blocks) {
        const dc = dataBytes.slice(offset, offset + blk.dataCount);
        offset += blk.dataCount;
        const ecCount = blk.totalCount - blk.dataCount;
        const rsPoly = errorCorrectPoly(ecCount);
        const modPoly = new Poly(dc, ecCount).mod(rsPoly);
        const ec = new Array(ecCount);
        for (let i = 0; i < ecCount; i++) {
          const idx = i + modPoly.length - ecCount;
          ec[i] = idx >= 0 ? modPoly.get(idx) : 0;
        }
        blockData.push(dc); blockEC.push(ec);
        maxDc = Math.max(maxDc, dc.length); maxEc = Math.max(maxEc, ec.length);
      }
      const codewords = [];
      for (let i = 0; i < maxDc; i++) for (const dc of blockData) if (i < dc.length) codewords.push(dc[i]);
      for (let i = 0; i < maxEc; i++) for (const ec of blockEC) if (i < ec.length) codewords.push(ec[i]);
      return { codewords, remainderBits: REMAINDER_BITS[version - 1] || 0 };
    }

    function bchDigit(data) { let d = 0; while (data !== 0) { d++; data >>>= 1; } return d; }
    const G15 = 0b1010011011;
    const G15_MASK = 0b101010000010010;
    const G18 = 0b1111100100101;
    function bchTypeInfo(data) {
      let d = data << 10;
      while (bchDigit(d) - bchDigit(G15) >= 0) d ^= (G15 << (bchDigit(d) - bchDigit(G15)));
      return ((data << 10) | d) ^ G15_MASK;
    }
    function bchTypeNumber(data) {
      let d = data << 12;
      while (bchDigit(d) - bchDigit(G18) >= 0) d ^= (G18 << (bchDigit(d) - bchDigit(G18)));
      return (data << 12) | d;
    }

    function buildMatrix(version, ecLevel, codewords) {
      const size = version * 4 + 17;
      const modules = Array.from({ length: size }, () => new Array(size).fill(null));

      function setFinder(row, col) {
        for (let r = -1; r <= 7; r++) {
          for (let c = -1; c <= 7; c++) {
            if (row + r < 0 || row + r >= size || col + c < 0 || col + c >= size) continue;
            const dark = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                         (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                         (r >= 2 && r <= 4 && c >= 2 && c <= 4);
            modules[row + r][col + c] = dark;
          }
        }
      }
      setFinder(0, 0); setFinder(size - 7, 0); setFinder(0, size - 7);

      for (let i = 8; i < size - 8; i++) {
        if (modules[i][6] === null) modules[i][6] = (i % 2 === 0);
        if (modules[6][i] === null) modules[6][i] = (i % 2 === 0);
      }

      const positions = ALIGNMENT_POSITIONS[version - 1];
      if (positions) {
        for (const row of positions) {
          for (const col of positions) {
            if (modules[row][col] !== null) continue;
            for (let r = -2; r <= 2; r++) {
              for (let c = -2; c <= 2; c++) {
                modules[row + r][col + c] = Math.max(Math.abs(r), Math.abs(c)) !== 1;
              }
            }
          }
        }
      }

      modules[size - 8][8] = true; // dark module

      for (let i = 0; i < 9; i++) {
        if (modules[8][i] === null) modules[8][i] = false;
        if (modules[i][8] === null) modules[i][8] = false;
      }
      for (let i = 0; i < 8; i++) {
        if (modules[8][size - 1 - i] === null) modules[8][size - 1 - i] = false;
        if (modules[size - 1 - i][8] === null) modules[size - 1 - i][8] = false;
      }

      if (version >= 7) {
        const vbits = bchTypeNumber(version);
        for (let i = 0; i < 18; i++) {
          const bit = ((vbits >> i) & 1) === 1;
          const a = 5 - Math.floor(i / 3);
          const b = (i % 3) + size - 11;
          modules[a][b] = bit;
          modules[b][a] = bit;
        }
      }

      let bitIndex = 0;
      function nextBit() {
        if (bitIndex < codewords.length * 8) {
          const byte = codewords[Math.floor(bitIndex / 8)];
          const bit = (byte >> (7 - (bitIndex % 8))) & 1;
          bitIndex++;
          return bit;
        }
        bitIndex++;
        return 0;
      }

      let row = size - 1, dir = -1;
      for (let col = size - 1; col > 0; col -= 2) {
        if (col === 6) col--;
        while (true) {
          for (let c2 = 0; c2 < 2; c2++) {
            const curCol = col - c2;
            if (modules[row][curCol] === null) modules[row][curCol] = nextBit() === 1;
          }
          row += dir;
          if (row < 0 || row >= size) { row -= dir; dir = -dir; break; }
        }
      }

      // Classify function modules (never masked) and apply the fixed mask.
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const inFinder = (r < 8 && c < 8) || (r < 8 && c >= size - 8) || (r >= size - 8 && c < 8);
          const inTiming = r === 6 || c === 6;
          const inFormatA = (r === 8 && c < 9) || (c === 8 && r < 9);
          const inFormatB = (r === 8 && c >= size - 8) || (c === 8 && r >= size - 8);
          let inAlign = false;
          if (positions) {
            for (const pr of positions) for (const pc of positions) {
              if (Math.abs(r - pr) <= 2 && Math.abs(c - pc) <= 2 && !inFinder) inAlign = true;
            }
          }
          const inVersion = version >= 7 && ((r < 6 && c >= size - 11) || (c < 6 && r >= size - 11));
          const isFunctionModule = inFinder || inTiming || inFormatA || inFormatB || inAlign || inVersion || (r === size - 8 && c === 8);
          if (!isFunctionModule && (r + c) % 2 === 0) modules[r][c] = !modules[r][c];
        }
      }

      const ecBits = { L: 1, M: 0, Q: 3, H: 2 }[ecLevel];
      const fbits = bchTypeInfo((ecBits << 3) | 0);
      for (let i = 0; i <= 5; i++) modules[i][8] = ((fbits >> i) & 1) === 1;
      modules[7][8] = ((fbits >> 6) & 1) === 1;
      modules[8][8] = ((fbits >> 7) & 1) === 1;
      modules[8][7] = ((fbits >> 8) & 1) === 1;
      for (let i = 9; i < 15; i++) modules[8][14 - i] = ((fbits >> i) & 1) === 1;
      for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = ((fbits >> i) & 1) === 1;
      for (let i = 0; i < 7; i++) modules[size - 1 - i][8] = ((fbits >> (i + 8)) & 1) === 1;

      return modules;
    }

    function encode(text, ecLevel, maxVersion) {
      const bytes = Array.from(textEncoder.encode(text));
      const version = chooseVersion(bytes.length, ecLevel, maxVersion);
      if (!version) return null;
      const { codewords } = buildCodewords(bytes, version, ecLevel);
      return { version, modules: buildMatrix(version, ecLevel, codewords) };
    }

    function toSvg(modules, modulePx, quietZone) {
      const size = modules.length;
      const total = size + quietZone * 2;
      const px = total * modulePx;
      let path = '';
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          if (modules[r][c]) {
            const x = (c + quietZone) * modulePx;
            const y = (r + quietZone) * modulePx;
            path += `M${x} ${y}h${modulePx}v${modulePx}h-${modulePx}z`;
          }
        }
      }
      return `<svg viewBox="0 0 ${px} ${px}" width="${px}" height="${px}" xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges">`
           + `<rect width="${px}" height="${px}" fill="#ffffff"/>`
           + `<path d="${path}" fill="#000000"/></svg>`;
    }

    return { encode, toSvg };
  })();

  // ==========================================================================
  // Clipboard
  // ==========================================================================
  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    // Fallback for non-secure contexts (e.g. file://)
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  // ==========================================================================
  // UI — state machine, theme, meters
  // ==========================================================================
  const els = {}; // populated in init()

  function setPanel(name) {
    document.body.setAttribute('data-state', name);
    document.querySelectorAll('.panel').forEach((p) => {
      p.setAttribute('data-active', p.dataset.panel === name ? 'true' : 'false');
    });
    const heading = document.querySelector(`.panel[data-panel="${name}"] h1`);
    if (heading) {
      heading.setAttribute('tabindex', '-1');
      heading.focus({ preventScroll: true });
    }
  }

  function setTheme(mode) {
    document.body.setAttribute('data-theme', mode);
  }

  function initTheme() {
    // No persistence, by design — this app stores nothing between visits.
    // Defaults to the system preference; the toggle overrides it for the
    // current tab only.
    let current = 'auto';
    els.themeToggle.addEventListener('click', () => {
      const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const effectiveIsDark = current === 'dark' || (current === 'auto' && systemDark);
      current = effectiveIsDark ? 'light' : 'dark';
      setTheme(current);
    });
  }

  function passwordStrength(pw) {
    if (!pw) return { score: 0, label: 'Enter a password' };
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 14) score++;
    if (pw.length >= 20) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    score = Math.min(score, 5);
    const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
    return { score, label: pw.length < 8 ? 'Too short — use 8+ characters' : labels[score] };
  }

  function updateStrengthUI(pw) {
    const { score, label } = passwordStrength(pw);
    const pct = (score / 5) * 100;
    els.strengthFill.style.width = pct + '%';
    els.strengthFill.style.backgroundColor =
      score <= 1 ? 'var(--danger)' : score <= 3 ? '#D9A441' : 'var(--success)';
    els.pwStrengthLabel.textContent = label;
  }

  function updateCreateAffordances() {
    const secret = els.secretInput.value;
    const pw = els.passwordInput.value;
    els.charCounter.textContent = `${secret.length.toLocaleString()} character${secret.length === 1 ? '' : 's'}`;
    const secretBytes = textEncoder.encode(secret).length;
    els.sizeEstimate.textContent = secret
      ? `Estimated encrypted size: ~${formatBytes(estimatePackageSize(secretBytes))}`
      : 'Encrypted size: —';
    els.encryptBtn.disabled = secret.trim().length === 0 || pw.length < 8;
  }

  function togglePasswordVisibility(input, button) {
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    button.setAttribute('aria-pressed', String(!showing));
    button.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  }

  function showError(message) {
    els.errorMessage.textContent = message;
    setPanel('error');
  }

  // ==========================================================================
  // Application Logic
  // ==========================================================================
  let lastPackageStr = null; // the package currently shown in the Share panel
  let pendingPackage = null; // parsed package awaiting a password in Load flow

  async function handleEncrypt() {
    const secret = els.secretInput.value;
    const password = els.passwordInput.value;
    if (!secret.trim() || password.length < 8) return;

    els.sealOverlay.setAttribute('data-active', 'true');
    els.encryptBtn.disabled = true;
    try {
      const pkg = await encryptSecret(secret, password);
      const packageStr = serializePackage(pkg);
      lastPackageStr = packageStr;

      // Best-effort clear of sensitive fields now that we're done with them.
      els.secretInput.value = '';
      els.passwordInput.value = '';
      updateCreateAffordances();
      updateStrengthUI('');

      populateSharePanel(packageStr);
      await new Promise((res) => setTimeout(res, 650)); // let the seal animation play
      setPanel('share');
      announce('Secret encrypted and ready to share.');
    } catch (e) {
      showError('Encryption failed: ' + e.message);
    } finally {
      els.sealOverlay.setAttribute('data-active', 'false');
    }
  }

  function populateSharePanel(packageStr) {
    const shareUrl = buildShareUrl(packageStr);
    els.shareUrl.value = shareUrl;
    els.packageOutput.value = packageStr;

    const qr = QR.encode(shareUrl, CONFIG.QR_EC_LEVEL, CONFIG.QR_MAX_VERSION);
    if (qr) {
      els.qrBox.innerHTML = QR.toSvg(qr.modules, CONFIG.QR_MODULE_PX, CONFIG.QR_QUIET_ZONE);
      els.qrWrap.hidden = false;
      els.qrDisabledHint.hidden = true;
    } else {
      els.qrWrap.hidden = true;
      els.qrDisabledHint.hidden = false;
    }
  }

  function resetToCreate() {
    lastPackageStr = null;
    els.shareUrl.value = '';
    els.packageOutput.value = '';
    els.qrBox.innerHTML = '';
    // Drop the fragment so a stale package isn't re-detected on next load.
    history.replaceState(null, '', window.location.pathname + window.location.search);
    setPanel('create');
  }

  function loadPackageFromString(str) {
    try {
      pendingPackage = deserializePackage(str);
      els.decryptPasswordInput.value = '';
      setPanel('password');
    } catch (e) {
      showError(e.message);
    }
  }

  async function handleDecrypt() {
    const password = els.decryptPasswordInput.value;
    if (!pendingPackage || !password) return;
    els.decryptBtn.disabled = true;
    try {
      const plaintext = await decryptPackage(pendingPackage, password);
      els.revealOutput.textContent = plaintext;
      els.decryptPasswordInput.value = '';
      setPanel('reveal');
      announce('Secret decrypted.');
    } catch (e) {
      showError(e.message);
    } finally {
      els.decryptBtn.disabled = false;
    }
  }

  function clearRevealedSecret() {
    els.revealOutput.textContent = '';
    pendingPackage = null;
  }

  // ==========================================================================
  // Event Listeners
  // ==========================================================================
  function wireEvents() {
    els.secretInput.addEventListener('input', updateCreateAffordances);
    els.passwordInput.addEventListener('input', () => {
      updateStrengthUI(els.passwordInput.value);
      updateCreateAffordances();
    });
    els.togglePassword.addEventListener('click', () =>
      togglePasswordVisibility(els.passwordInput, els.togglePassword));
    els.encryptBtn.addEventListener('click', handleEncrypt);
    els.goToLoad.addEventListener('click', () => setPanel('load'));

    els.copyUrlBtn.addEventListener('click', async () => {
      const ok = await copyText(els.shareUrl.value);
      announce(ok ? 'Link copied.' : 'Could not copy — select and copy manually.');
    });
    els.copyPackageBtn.addEventListener('click', async () => {
      const ok = await copyText(els.packageOutput.value);
      announce(ok ? 'Encrypted package copied.' : 'Could not copy — select and copy manually.');
    });
    els.downloadPackageBtn.addEventListener('click', () => {
      downloadBlob('secret.secret', lastPackageStr || els.packageOutput.value, 'application/octet-stream');
    });
    els.createAnotherBtn.addEventListener('click', resetToCreate);

    els.dropzone.addEventListener('click', () => els.fileInput.click());
    els.dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); els.fileInput.click(); }
    });
    ['dragenter', 'dragover'].forEach((evt) =>
      els.dropzone.addEventListener(evt, (e) => { e.preventDefault(); els.dropzone.dataset.drag = 'true'; }));
    ['dragleave', 'drop'].forEach((evt) =>
      els.dropzone.addEventListener(evt, (e) => { e.preventDefault(); els.dropzone.dataset.drag = 'false'; }));
    els.dropzone.addEventListener('drop', (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) readFileAsPackage(file);
    });
    els.fileInput.addEventListener('change', () => {
      const file = els.fileInput.files && els.fileInput.files[0];
      if (file) readFileAsPackage(file);
    });

    els.pasteInput.addEventListener('input', () => {
      els.continueLoadBtn.disabled = els.pasteInput.value.trim().length === 0;
    });
    els.continueLoadBtn.addEventListener('click', () => loadPackageFromString(els.pasteInput.value));

    els.toggleDecryptPassword.addEventListener('click', () =>
      togglePasswordVisibility(els.decryptPasswordInput, els.toggleDecryptPassword));
    els.decryptBtn.addEventListener('click', handleDecrypt);
    els.decryptPasswordInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleDecrypt();
    });
    els.backFromPassword.addEventListener('click', resetToCreate);

    els.copySecretBtn.addEventListener('click', async () => {
      const ok = await copyText(els.revealOutput.textContent);
      announce(ok ? 'Secret copied.' : 'Could not copy — select and copy manually.');
    });
    els.downloadSecretBtn.addEventListener('click', () => {
      downloadBlob('secret.txt', els.revealOutput.textContent, 'text/plain');
    });
    els.hideSecretBtn.addEventListener('click', () => {
      const hidden = els.revealOutput.style.filter === 'blur(8px)';
      els.revealOutput.style.filter = hidden ? '' : 'blur(8px)';
      els.hideSecretBtn.textContent = hidden ? 'Hide' : 'Show';
    });
    els.clearSecretBtn.addEventListener('click', () => {
      clearRevealedSecret();
      resetToCreate();
    });

    els.errorBackBtn.addEventListener('click', resetToCreate);
  }

  function readFileAsPackage(file) {
    const reader = new FileReader();
    reader.onload = () => loadPackageFromString(String(reader.result));
    reader.onerror = () => showError('Could not read that file.');
    reader.readAsText(file);
  }

  // ==========================================================================
  // Initialization
  // ==========================================================================
  function cacheElements() {
    const ids = [
      'themeToggle', 'stage', 'secretInput', 'charCounter', 'sizeEstimate',
      'passwordInput', 'togglePassword', 'strengthFill', 'pwStrengthLabel',
      'encryptBtn', 'goToLoad', 'sealOverlay',
      'shareUrl', 'copyUrlBtn', 'qrWrap', 'qrBox', 'qrDisabledHint',
      'packageOutput', 'copyPackageBtn', 'downloadPackageBtn', 'createAnotherBtn',
      'dropzone', 'fileInput', 'pasteInput', 'continueLoadBtn',
      'decryptPasswordInput', 'toggleDecryptPassword', 'decryptBtn', 'backFromPassword',
      'revealOutput', 'copySecretBtn', 'downloadSecretBtn', 'hideSecretBtn', 'clearSecretBtn',
      'errorMessage', 'errorBackBtn',
    ];
    for (const id of ids) els[id] = document.getElementById(id);
  }

  function init() {
    cacheElements();
    wireEvents();
    initTheme();
    updateCreateAffordances();
    updateStrengthUI('');

    const hashPackage = extractPackageFromHash();
    if (hashPackage) {
      loadPackageFromString(hashPackage);
    } else {
      setPanel('create');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
