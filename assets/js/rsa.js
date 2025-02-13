// Library JSEncrypt untuk RSA
function encryptPassword(password, publicKey) {
    const encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);
    return encrypt.encrypt(password);
}