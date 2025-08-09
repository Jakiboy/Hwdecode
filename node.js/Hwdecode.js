const BLOCKSIZE = 0X14;
const PASSWORD = "6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498"

Uint8Array.prototype.writeUInt32LE = function (value, offset) {
	for (let i = 0; i < 4; i++) {
		this[offset + i] = value & 0xFF;
		value = value >> 8;
	}
}

/**
 * Decodes an encoded string into a binary buffer.
 */
function decodeAesStringToBuffer(encryptedStr) {
	let buf = new Uint8Array(encryptedStr.split('').map(c => c.charCodeAt(0)));
	for (let i = 0; i < buf.length; i++) {
		if (0x7e == buf[i]) // character ~
			buf[i] = 0x1e;
		else
			buf[i] = buf[i] - 0x21; // chracter !
	}
	return buf;
}

/**
 * Converting sequence of 5 values into a single numeric value using a weighted sum.
 */
function encodeAesBufferToLong(buffer) {
	let output = 0;
	let v3 = 1;
	for (let i = 0; i < 5; i++) {
		output += v3 * buffer[i];
		v3 *= 0x5D;
	}
	return output;
}

/**
 * Convert plain string in buffer to binary.
 */
function plainToBin(buffer) {

	if (buffer.length % 5 != 0) return;

	let output = new Uint8Array(buffer.length * 4 / 5);
	let periodFive = 0;
	for (let i = 0; i != output.length; i += 4) {
		let _long = encodeAesBufferToLong(buffer.slice(periodFive, periodFive + 5));
		output.writeUInt32LE(_long, i);
		periodFive += 5;
	}
	return output;
}

/**
 * Format & check encrypted string.
 */
function format(encryptedStr) {
	if (encryptedStr.length < 3) return '';

	if ("$" != encryptedStr[0] || "2" != encryptedStr[1] || "$" != encryptedStr[encryptedStr.length - 1]) {
		return '';
	}
	return encryptedStr.substr(2, encryptedStr.length - 3);
}

/**
 * Decrypt string, Encrypted by Huawei router.
 */
function Decrypt(input, key) {
	if (!input instanceof Uint8Array && typeof input != "string")
		return '';

	if (!key instanceof Uint8Array && typeof key != "string")
		return '';

	if (key instanceof Uint8Array)
		key = toHexString(key);

	let decrypted = '';
	let unvisible = decodeAesStringToBuffer(format(input));
	let blockCount = (unvisible.length / BLOCKSIZE) >> 0;
	if (unvisible.length != BLOCKSIZE * blockCount) return '';

	let IV = Global_IV = plainToBin(unvisible.slice(blockCount * BLOCKSIZE - BLOCKSIZE, blockCount * BLOCKSIZE));
	const dataAll = plainToBin(unvisible.slice(0, blockCount * BLOCKSIZE - BLOCKSIZE));

	let result = CryptoJS.AES.decrypt(toHexString(dataAll), CryptoJS.enc.Hex.parse(key), {
		iv: CryptoJS.enc.Hex.parse(toHexString(IV)),
		mode: CryptoJS.mode.CBC,
		format: CryptoJS.format.Hex
	});
	result.sigBytes = dataAll.length;

	return result.toString(CryptoJS.enc.Utf8)

}

/**
 * Convert bytes to HEX string.
 */
function toHexString(bytes) {
	return bytes.reduce(function (str, byte) {
		return str + byte.toString(16).padStart(2, '0');
	}, '');
}

/**
 * Decode Cipher with hardcoded HEX
 */
function decodeCipher(cipher) {
	return Decrypt(he.decode(cipher.trim()), PASSWORD);
}

/**
 * Test
 */
console.log(decodeCipher('$2WHVM5s_OoD:|T#>(DE}"|XITBzAou<Tz&CBZ!%dK$'));
