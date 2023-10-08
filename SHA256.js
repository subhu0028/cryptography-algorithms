


const crypto = require("crypto");

// Function to generate RSA key pair
function generateRSAKeyPair() {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: "spki",
			format: "pem",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "pem",
		},
	});

	return { publicKey, privateKey };
}

// Function to encrypt a message using RSA public key
function encryptWithRSA(message, publicKey) {
	const encryptedData = crypto.publicEncrypt(
		{
			key: publicKey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: "sha256",
		},
		Buffer.from(message, "utf-8")
	);

	return encryptedData.toString("base64");
}

// Function to decrypt a message using RSA private key
function decryptWithRSA(encryptedMessage, privateKey) {
	const decryptedData = crypto.privateDecrypt(
		{
			key: privateKey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: "sha256",
		},
		Buffer.from(encryptedMessage, "base64")
	);

	return decryptedData.toString("utf-8");
}

// Usage example
function main() {
	const { publicKey, privateKey } = generateRSAKeyPair();

	const readline = require("readline").createInterface({
		input: process.stdin,
		output: process.stdout,
	});

	readline.question("Enter the message to be encrypted: ", (message) => {
		const encryptedMessage = encryptWithRSA(message, publicKey);
		console.log("Encrypted Message:", encryptedMessage);

		const decryptedMessage = decryptWithRSA(encryptedMessage, privateKey);
		console.log("Decrypted Message:", decryptedMessage);

		readline.close();
	});
}

main();
