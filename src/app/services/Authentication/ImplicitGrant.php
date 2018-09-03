<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authentication;


use Oauth\Services\Exceptions\Storage\NoEntityException;
use Psr\Http\Message\ServerRequestInterface;

class ImplicitGrant extends GrantType
{
    public function authenticateClient(array $queryParameters): bool
    {
        try {
            // find the client
            $client = $this->clientStorage->fetch($queryParameters['client_id']);

            // Match scope
            $queryScope = explode(' ', $queryParameters['scope']);
            $scopeOut = array_diff($queryScope, $client->getScope());
            if (!empty($scopeOut)) {
                $this->errorsMessages['scope'] = 'This client have no access for this scope element : [' . implode(', ', $scopeOut) . ']';
            }

            // Check redirect_uri
            if (!\in_array($queryParameters['redirect_uri'], $client->getRedirectUri(), true)) {
                $this->errorsMessages['redirect_uri'] = 'This redirect uri is not configured for this client';
            }

            if (empty($this->errorsMessages) && empty($this->mc->get('auth_state:' . $client->getClientIdentification()))) {
                error_log('yolo');
                $this->mc->add('auth_state:' . $client->getClientIdentification(), $queryParameters['state'], 300);
            }

        } catch (NoEntityException $e) {
            $this->errorsMessages['client_id'] = 'This client does not exist';
        }

        return empty($this->errorsMessages);
    }

    public function authenticateUser(ServerRequestInterface $request): bool
    {
        // TODO: Implement authenticateUser() method.
    }
}