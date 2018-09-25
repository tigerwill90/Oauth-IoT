<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;

use Jose\Component\Core\JWKSet;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Memcached;
use Oauth\Services\IntrospectionInterface;
use Oauth\Services\Storage\ResourceStorageInterface;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class IntrospectionEndpoint
{
    /** @var IntrospectionInterface  */
    private $introspection;

    /** @var Memcached  */
    private $mc;

    /** @var LoggerInterface  */
    private $logger;

    /** @var ResourceStorageInterface */
    private $resourceStorage;

    public function __construct(IntrospectionInterface $introspection, Memcached $mc, ResourceStorageInterface $resourceStorage, LoggerInterface $logger = null)
    {
        $this->introspection = $introspection;
        $this->logger = $logger;
        $this->mc = $mc;
        $this->resourceStorage = $resourceStorage;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {

        $headers = $request->getHeader('HTTP_AUTHORIZATION');
        $identification = null;

        if (isset($headers[0]) && preg_match('/Basic\s+(.*)$/i', $headers[0],$matches)) {
            $identification =  $matches[1];
        } else {
            $body = $response->getBody();
            $body->write(json_encode(['error' => 'invalid resource']));
            return $response
                ->withBody($body)
                ->withHeader('content-type', 'application/json')
                ->withStatus(401);
        }

        try {
            $resource = $this->resourceStorage->fetchByResourceIdentification(base64_decode($identification));
            // TODO check password is TLS on
        } catch (NoEntityException $e) {
            $body = $response->getBody();
            $body->write(json_encode(['error' => 'invalid resource']));
            return $response
                ->withBody($body)
                ->withHeader('content-type', 'application/json')
                ->withStatus(401);
        }

        $jwkSet = $this->mc->get($resource->getAudience());

        if (empty($jwkSet)) {
            $jwkSet = JWKSet::createFromKeys([]);
        }

        $this->log(print_r($jwkSet, true));

        $this->introspection
            ->withChecker('standard')
            ->setResource($resource)
            ->setRequestParameterToVerify('token')
            ->setMandatoryClaims([IntrospectionInterface::CLAIM_EXP, IntrospectionInterface::CLAIM_AUD]);

        if ($resource->getPopMethod() === 'introspection') {
            $this->introspection->setPopKey($resource->isTls(), $resource->getResourceSecret());
        }

        $isValidToken = $this->introspection->introspectToken($request, $jwkSet, true);

        $body = $response->getBody();
        $body->write(json_encode($this->introspection, JSON_UNESCAPED_SLASHES));
        $newResponse = $response
            ->withBody($body)
            ->withHeader('content-type', 'application/json');

        if ($isValidToken) {
            if (!empty($this->introspection->getInvalidClaims())) {
                $this->log(print_r($this->introspection->getInvalidClaims(), true), ['info' => 'invalid claims']);
            }
            return $newResponse;
        }

        return $newResponse->withStatus(401);
    }

    /**
     * @param string $message
     * @param array $context
     * @return IntrospectionEndpoint
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
