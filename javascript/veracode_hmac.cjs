/* set Veracode API credentials in api_id and api_key in environment*/
var CryptoJS = require('crypto-js');

const id = process.env.API_ID;
if (!id) {
    throw new Error("Environment does not have an 'API_ID'. Please ensure you have configured a Veracode environment.");
}
const key = process.env.API_KEY;
if (!key) {
    throw new Error("Environment does not have an 'API_KEY'. Please ensure you have configured a Veracode environment.");
}

const authorizationScheme = 'VERACODE-HMAC-SHA-256';
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message, key_hex) {
    return CryptoJS.HmacSHA256(message, CryptoJS.enc.Hex.parse(key_hex)).toString(CryptoJS.enc.Hex);
}

function calculateDataSignature(apikey, nonceBytes, dateStamp, data) {
    let kNonce = computeHashHex(nonceBytes, apikey);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    return computeHashHex(data, kSig);
}

function newNonce() {
    return CryptoJS.lib.WordArray.random(nonceSize).toString().toUpperCase();
}

function toHexBinary(input) {
    return CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(input));
}

function removePrefixFromApiCredential(input) {
    return input.split('-').at(-1);
}

function calculateVeracodeAuthHeader(httpMethod) {
    const formattedId = removePrefixFromApiCredential(id);
    const formattedKey = removePrefixFromApiCredential(key);

    let parsedUrl = 'api.veracode.com';

    let data = `id=${formattedId}&host=${parsedUrl.hostname}&url=${parsedUrl.path}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce();
    let dataSignature = calculateDataSignature(formattedKey, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${formattedId},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    return authorizationScheme + " " + authorizationParam;
}

module.exports = { calculateVeracodeAuthHeader }
