<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 5:18 PM
 */

namespace Oauth\Services\Validators\CustomValidators;

use Oauth\Services\Validators\Rules\ClientNameRule;
use Oauth\Services\Validators\Rules\ClientTypeRule;
use Oauth\services\Validators\Rules\GrantTypeRule;
use Oauth\Services\Validators\Rules\RedirectUriRule;
use Oauth\Services\Validators\Rules\ScopeRule;
use Oauth\Services\Validators\ParameterValidator;
use Oauth\Services\Validators\Validator;

class ClientRegistrationValidator extends ParameterValidator
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
        parent::__construct();
    }
}