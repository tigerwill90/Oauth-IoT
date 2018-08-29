<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Helpers\AesHelperInterface;
use Oauth\Services\ClaimsCheckerRules;
use Oauth\Services\IntrospectionInterface;
use phpseclib\Crypt\AES;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class IntrospectionController
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

        $isValidToken =$this->introspection
            ->injectClaimsChecker(new ClaimsCheckerRules())
            ->setRequestParameterToVerify('token')
            ->setClaimsToVerify([IntrospectionInterface::CLAIM_EXP, IntrospectionInterface::CLAIM_JTI])
            ->setActiveResponseParameter([], null, null, ['key' => $encryptedKey])
            ->introspectToken($request, getenv('KEY'), 'oct');

        $body = $response->getBody();
        $body->write($this->introspection->getJsonResponse());
        $newResponse = $response
            ->withBody($body)
            ->withHeader('content-type', 'application/json');

        if ($isValidToken) {
            $this->logger->info(print_r($this->introspection->getInvalidClaims(), true), ['info' => 'invalid claims']);
            return $newResponse;
        }

        return $newResponse->withStatus(401);
    }
}
