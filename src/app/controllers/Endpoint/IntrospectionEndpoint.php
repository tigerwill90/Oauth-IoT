<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:03 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\IntrospectionInterface;
use Oauth\Services\Storage\ResourceStorageInterface;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class IntrospectionEndpoint
{
    /** @var IntrospectionInterface  */
    private $introspection;

    /** @var LoggerInterface  */
    private $logger;

    /** @var ResourceStorageInterface */
    private $resourceStorage;

    public function __construct(IntrospectionInterface $introspection, ResourceStorageInterface $resourceStorage, LoggerInterface $logger = null)
    {
        $this->introspection = $introspection;
        $this->logger = $logger;
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
            $credentials = explode(':', base64_decode($identification), 2);
            $resource = $this->resourceStorage->fetchByResourceIdentification($credentials[0]);
            if ($resource->isTls() && $resource->getResourceSecret() !== $credentials[1]) {
                $body = $response->getBody();
                $body->write(json_encode(['error' => 'invalid resource']));
                return $response
                    ->withBody($body)
                    ->withHeader('content-type', 'application/json')
                    ->withStatus(401);
            }
        } catch (NoEntityException $e) {
            $body = $response->getBody();
            $body->write(json_encode(['error' => 'invalid resource']));
            return $response
                ->withBody($body)
                ->withHeader('content-type', 'application/json')
                ->withStatus(401);
        }

        $this->introspection
            ->withChecker('standard')
            ->setAudience($resource)
            ->setRequestParameterToVerify('token')
            ->setMandatoryClaims([IntrospectionInterface::CLAIM_EXP, IntrospectionInterface::CLAIM_AUD]);

        if ($resource->getPopMethod() === 'introspection') {
            $this->introspection->setPopKey($resource->isTls(), $resource->getResourceSecret());
        }

        $isValidToken = $this->introspection->introspectToken($request, null, true);

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
