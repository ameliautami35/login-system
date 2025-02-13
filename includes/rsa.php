<?php
function generateRSAKeys() {
    $config = [
        "digest_alg" => "sha512",
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    // Generate key pair
    $res = openssl_pkey_new($config);

    if ($res === false) {
        throw new Exception("Gagal menghasilkan kunci RSA: " . openssl_error_string());
    }

    // Get private key
    $privateKey = '';
    if (!openssl_pkey_export($res, $privateKey)) {
        throw new Exception("Gagal mengekspor kunci privat: " . openssl_error_string());
    }

    // Get public key
    $publicKeyDetails = openssl_pkey_get_details($res);
    if ($publicKeyDetails === false) {
        throw new Exception("Gagal mendapatkan detail kunci publik: " . openssl_error_string());
    }
    $publicKey = $publicKeyDetails["key"];

    return [
        'private' => $privateKey,
        'public'  => $publicKey,
    ];
}
?>