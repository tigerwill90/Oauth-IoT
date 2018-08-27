<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Introspection\IExtended;
use Oauth\Services\Introspection\IntrospectionInterface;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class IntrospectionController
{

    /** @var IntrospectionInterface  */
    private $introspection;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(IntrospectionInterface $introspection, LoggerInterface $logger)
    {
        $this->introspection = $introspection;
        $this->logger = $logger;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $isValidToken =$this->introspection
            ->injectClaimsChecker(new IExtended())
            ->setRequestParameterToVerify('token')
            ->setClaimsToVerify([IntrospectionInterface::CLAIM_EXP, 'wrongclaim', 'nbf', 'iss', 'aud', 'iat', 'COLO'])
            ->setResponseParameter(['active', 'iat', 'wrongresp', 'nbf', 'username'], ['key' => 'supersecret'])
            ->addUserInformation('Toto', 666)
            ->introspectToken($request, getenv('KEY'), 'oct');

        $body = $response->getBody();
        $body->write($this->introspection->getJsonResponse());
        $newResponse = $response
            ->withBody($body)
            ->withHeader('content-type', 'application/json');

        if ($isValidToken) {
            return $newResponse;
        }

        return $newResponse->withStatus(401);
    }
}
