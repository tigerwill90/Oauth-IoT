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


final class IntrospectionController
{

    /** @var IntrospectionInterface  */
    private $introspection;

    public function __construct(IntrospectionInterface $introspection)
    {
        $this->introspection = $introspection;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $isValidToken =$this->introspection
            ->injectExtendedClass(new IExtended())
            ->configureIntrospectParameters('token')
            ->configureIntrospectClaims([IntrospectionInterface::CLAIM_EXP, 'wrongclaim', 'nbf', 'iss', 'aud', 'iat'])
            ->configureIntrospectResponse(['active', 'iat', 'wrongresp', 'nbf', 'username'])
            ->introspectToken($request);

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
