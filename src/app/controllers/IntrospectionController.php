<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;
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

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $this->introspection
            ->setIntrospectClaims([IntrospectionInterface::CLAIM_EXP, 'wrontclaim', 'nbf', 'iss', 'aud', 'iat'])
            ->setIntrospectionResponse(['active', 'username', 'yolo'])
            ->introspectToken($request);

        $body = $response->getBody();
        $body->write(json_encode(['foo' => 'bar']));
        return $response->withBody($body);
    }
}
