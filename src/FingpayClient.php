<?php
namespace Yts\Fingpay;

use GuzzleHttp\Client;

class FingpayClient
{
    protected $config;
    protected $client;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->client = new Client([
            'base_uri' => rtrim($config['base_url'], '/'),
            'timeout' => $config['timeout'] ?? 30
        ]);
    }

    protected function buildHeaders($jsonPayload)
    {
        $timestamp = date($this->config['timestamp_format'] ?? 'd/m/Y H:i:s');

        $distributorId = $this->config['distributor_id'] ?? 0;
        $apiKey = $this->config['api_key'] ?? '';

        $hashSource = $jsonPayload . $this->config['security_key'] . $timestamp;
        $sha = hash('sha256', $hashSource, true);
        $hash = base64_encode($sha);

        return [
            'trnTimestamp' => $timestamp,
            'distributorId' => $distributorId ?: 0,
            'apiKey' => $apiKey ?: '',
            'hash' => $hash,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
    }

    protected function encryptPayload($plaintext)
    {
        $key = $this->normalizeKey($this->config['pre_shared_key']);
        $iv = random_bytes(12);
        $tag = null;

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            throw new \Exception('Encryption failed: ' . openssl_error_string());
        }

        return base64_encode($iv . $ciphertext . $tag);
    }

    protected function decryptPayload($base64)
    {
        $key = $this->normalizeKey($this->config['pre_shared_key']);
        $decoded = base64_decode($base64);
        if ($decoded === false) {
            throw new \Exception('Base64 decode failed');
        }

        $iv = substr($decoded, 0, 12);
        $tag = substr($decoded, -16);
        $ciphertext = substr($decoded, 12, strlen($decoded) - 12 - 16);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new \Exception('Decryption failed: ' . openssl_error_string());
        }

        return $plaintext;
    }

    protected function normalizeKey($key)
    {
        if (strlen($key) === 32) {
            return $key;
        }
        if (ctype_xdigit($key) && strlen($key) === 64) {
            return hex2bin($key);
        }
        return substr(hash('sha256', $key, true), 0, 32);
    }

    protected function callApi($path, array $payload)
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $encryptedBody = $this->encryptPayload($json);
        $headers = $this->buildHeaders($json);

        $res = $this->client->post($path, [
            'headers' => $headers,
            'body' => $encryptedBody,
        ]);

        $body = (string) $res->getBody();

        try {
            $decrypted = $this->decryptPayload($body);
            $decoded = json_decode($decrypted, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $decoded;
            }
        } catch (\Exception $e) {
            // fallback
        }

        $parsed = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $parsed;
        }

        return ['raw' => $body];
    }

    public function generateUpiLink($vpa, $distributorName, $transactionId, $amount = '', $mcc = null)
    {
        $amountParam = $amount !== '' ? $amount : '';
        $mccParam = $mcc !== null ? '&mc=' . urlencode($mcc) : '';

        return "upi://pay?pa={$vpa}&pn=" . rawurlencode($distributorName) . "&tr={$transactionId}&am={$amountParam}&cu=INR{$mccParam}";
    }

    public function generatePgLink($invoiceIdentifier, $retailerIdentifier)
    {
        $base = $this->config['pg_base_url'] ?? 'https://fingpayuat.tapits.in/fpcmsweb/fingpayPaymentGateway.html';
        return $base . '?bunq=' . rawurlencode($invoiceIdentifier) . '&ret=' . rawurlencode($retailerIdentifier);
    }

    public function createUpiRequest(array $payload)
    {
        return $this->callApi('/upi/request', $payload);
    }

    public function upiHistory(array $payload)
    {
        return $this->callApi('/upi/transaction/history', $payload);
    }

    public function statusCheck(array $payload)
    {
        return $this->callApi('/upi/status/check', $payload);
    }
}
