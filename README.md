# yts-fingpay
Fingpay PHP library to integrate UPI / NEFT / RTGS using virtual accounts, using dynamic and static QR codes for UPI payments

# Fingpay PHP Client

A PHP client for the Fingpay API that supports:
- AES-256-GCM encryption/decryption
- UPI and PG link generation
- API calls for UPI request, history, and status checks

## Installation

```bash
composer require yts/fingpay
```

## Usage

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Yts\Fingpay\FingpayClient;

$config = [
    'base_url'        => 'https://fingpay.example.com',
    'security_key'    => 'your_security_key',
    'pre_shared_key'  => 'your_pre_shared_key',
    'distributor_id'  => '1234',
    'api_key'         => 'your_api_key',
];

$fingpay = new FingpayClient($config);

// Create UPI request
$response = $fingpay->createUpiRequest([
    'amount' => '100',
    'vpa' => 'test@upi',
]);

print_r($response);
```

## License
MIT
