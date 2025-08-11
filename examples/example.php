<?php
require __DIR__ . '/../vendor/autoload.php';

use Yts\Fingpay\FingpayClient;

$config = [
    'base_url'        => 'https://fingpay.example.com',
    'security_key'    => 'your_security_key',
    'pre_shared_key'  => 'your_pre_shared_key',
    'distributor_id'  => '1234',
    'api_key'         => 'your_api_key',
];

$client = new FingpayClient($config);

// Example API call
$response = $client->statusCheck([
    'transactionId' => 'TXN12345'
]);

print_r($response);
