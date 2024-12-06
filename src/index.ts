import crypto from 'crypto';
import sqlite3, { Database } from 'sqlite3';
import { execSync } from 'child_process';
import { platform } from 'os';

type Row = {
  creation_utc: number;
  host_key: string;
  top_frame_site_key: string;
  name: string;
  value: string;
  encrypted_value: Buffer;
  path: string;
  expires_utc: number;
  is_secure: number;
  is_httponly: number;
  last_access_utc: number;
  has_expires: number;
  is_persistent: number;
  priority: number;
  samesite: number;
  source_scheme: number;
  source_port: number;
  last_update_utc: number;
  source_type: number;
  has_cross_site_ancestor: number;
};

// NOTE: 쿠키 정보는 OS 에 저장된 key 값으로 암호화 되어있다.
const getEncryptionKey = (): Buffer<ArrayBuffer> => {
  if (platform() !== 'darwin') {
    throw new Error('MacOS 만 지원');
  }
  const key = execSync('security find-generic-password -wa "Chrome"').toString().trim();
  return Buffer.from(key, 'base64');
};

const decryptCookie = (key: Buffer, encryptedValue: Buffer): string => {
  const iv = encryptedValue.slice(3, 15); // Extract IV from encrypted value
  const cipherText = encryptedValue.slice(15); // Cipher text after IV
  console.log(iv, cipherText);
  console.log(encryptedValue.slice(-16));
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(encryptedValue.slice(-16)); // Set Auth Tag (last 16 bytes)
  const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  return decrypted.toString('utf-8');
};

const selectQuery = async (db: Database, sql: string): Promise<Row[]> =>
  new Promise((resolve, reject) => {
    db.all(sql, {}, (error, rows) => {
      if (error !== null) {
        return reject(error);
      }
      resolve(rows as Row[]);
    });
  });

const run = async () => {
  const key = getEncryptionKey();
  console.log(key);
  console.log(key.toString());
  const CHROME_COOKIE_STORE_PATH = '/Users/mk-am16-075/Library/Application Support/Google/Chrome/Default/Cookies';
  const db = new sqlite3.Database(CHROME_COOKIE_STORE_PATH);
  const rows = await selectQuery(db, `SELECT * FROM cookies WHERE host_key = '.perf.kurly.com'`);
  const value = decryptCookie(key, rows[0].encrypted_value);
  console.log(value);
};

run();
/*
function getEncryptionKey() {
    const platform = os.platform();
    if (platform === 'win32') {
        // Windows DPAPI: Run PowerShell command to get key
        const key = execSync(
            'powershell -Command "Get-ItemProperty -Path HKCU:\\Software\\Microsoft\\Protect\\* | ForEach-Object { $_.MasterKey }"'
        ).toString().trim();
        return Buffer.from(key, 'base64');
    } else if (platform === 'darwin') {
        // MacOS Keychain: Extract key using security command
        const key = execSync(
            'security find-generic-password -wa "Chrome"'
        ).toString().trim();
        return Buffer.from(key, 'base64');
    } else if (platform === 'linux') {
        // Linux Gnome Keyring: Extract key
        const key = execSync(
            "secret-tool lookup application chrome | head -n 1"
        ).toString().trim();
        return Buffer.from(key, 'base64');
    } else {
        throw new Error('Unsupported OS platform');
    }
}
*/

/**
 * Decrypts a Chrome-encrypted cookie value.
 * @param {Buffer} encryptedValue - The encrypted cookie value.
 * @returns {string} - Decrypted cookie value.
 */
/*
function decryptCookie(encryptedValue) {
  const key = getEncryptionKey();
  const iv = encryptedValue.slice(3, 15); // Extract IV from encrypted value
  const cipherText = encryptedValue.slice(15); // Cipher text after IV

  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(encryptedValue.slice(-16)); // Set Auth Tag (last 16 bytes)
  const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  return decrypted.toString('utf-8');
}
 */

/**
 * Re-encrypts a cookie value using AES-128-GCM.
 * @param {string} value - The plaintext cookie value.
 * @returns {Buffer} - Encrypted cookie value.
 */
/*
function encryptCookie(value) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12); // Chrome uses a 12-byte IV
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(value, 'utf-8'), cipher.final()]);
  const authTag = cipher.getAuthTag(); // Get Auth Tag (16 bytes)

  // Chrome's format: `v10` prefix (3 bytes) + IV (12 bytes) + Encrypted value + Auth Tag
  return Buffer.concat([Buffer.from('v10'), iv, encrypted, authTag]);
}
 */
