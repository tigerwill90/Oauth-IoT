<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Oauth\Services\Helpers\AesHelperInterface;
use Oauth\Services\ClaimsCheckerRules;
use Oauth\Services\IntrospectionInterface;
use phpseclib\Crypt\AES;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class IntrospectionEndpoint
{

    /** @var IntrospectionInterface  */
    private $introspection;

    /** @var LoggerInterface  */
    private $logger;

    /** @var  AesHelperInterface*/
    private $aesHelper;

    public function __construct(IntrospectionInterface $introspection, LoggerInterface $logger, AesHelperInterface $aesHelper)
    {
        $this->introspection = $introspection;
        $this->logger = $logger;
        $this->aesHelper = $aesHelper;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $encryptedKey = $this->aesHelper
            ->setMode(AES::MODE_ECB)
            ->aesEncrypt('abcdef!hij012345', 'AaBbCcDdEe0123Az', false);

        $jwk = JWK::create([
            'kty' => 'oct',
            'k' => getenv('KEY'),
            'alg' => 'HS256',
            'use' => 'sig',
            'enc' => 'A256CBC-HS512',
            'kid' => '12345'
        ]);

        $jwkSet = JWKSet::createFromKeys([$jwk]);

        $isValidToken =$this->introspection
            ->withChecker('standard')
            ->setRequestParameterToVerify('token')
            ->setMandatoryClaims([IntrospectionInterface::CLAIM_EXP, IntrospectionInterface::CLAIM_JTI, IntrospectionInterface::CLAIM_AUD])
            ->setActiveResponseParameter(['exp'], null, null, ['key' => $encryptedKey])
            ->introspectToken($request, $jwkSet, true);

        $body = $response->getBody();
        $body->write(json_encode($this->introspection, JSON_UNESCAPED_SLASHES));
        $newResponse = $response
            ->withBody($body)
            ->withHeader('content-type', 'application/json');

        if ($isValidToken) {
            if (!empty($this->introspection->getInvalidClaims())) {
                $this->logger->info(print_r($this->introspection->getInvalidClaims(), true), ['info' => 'invalid claims']);
            }
            return $newResponse;
        }

        return $newResponse->withStatus(401);
    }
}
