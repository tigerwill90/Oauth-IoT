<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 5:18 PM
 */

namespace Oauth\Services\Validators\RequestValidators;

use Oauth\Services\Validators\Parameters\ClientNameRule;
use Oauth\Services\Validators\Parameters\ClientTypeRule;
use Oauth\services\Validators\Parameters\GrantTypeRule;
use Oauth\Services\Validators\Parameters\RedirectUriRule;
use Oauth\Services\Validators\Parameters\ScopeRule;

class ClientRegistrationRequestValidator extends RequestValidator
{
    public function __construct()
    {
        $this->parametersValidator = [
            'client_name' => new ClientNameRule(),
            'grant_type' => new GrantTypeRule(),
            'client_type' => new ClientTypeRule(),
            'redirect_uri' => new RedirectUriRule(),
            'scope' => new ScopeRule()
        ];
    }
}