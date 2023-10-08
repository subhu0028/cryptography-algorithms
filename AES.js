
const crypto = require('crypto');

// Function to encrypt text
function aes_encrypt(input_text) {
    // Generate a random 256-bit AES key
    const key = crypto.randomBytes(32);

    // Create an AES cipher object
    const cipher = crypto.createCipher('aes-256-cbc', key);

    // Encrypt the input text
    let ciphertext = cipher.update(input_text, 'utf-8', 'hex');
    ciphertext += cipher.final('hex');

    return {
        key: key.toString('hex'),
        ciphertext: ciphertext,
    };
}

// Function to decrypt text
function aes_decrypt(key, ciphertext) {
    // Create a decipher object
    const decipher = crypto.createDecipher('aes-256-cbc', Buffer.from(key, 'hex'));

    // Decrypt the ciphertext
    let decrypted_text = decipher.update(ciphertext, 'hex', 'utf-8');
    decrypted_text += decipher.final('utf-8');

    return decrypted_text;
}

// Example usage
const input_text = "Hello, World!";
const encryptedData = aes_encrypt(input_text);

console.log("Original Text: ", input_text);
console.log("Encryption Key: ", encryptedData.key);
console.log("Encrypted Text: ", encryptedData.ciphertext);

const decryptedText = aes_decrypt(encryptedData.key, encryptedData.ciphertext);
console.log("Decrypted Text: ", decryptedText);

