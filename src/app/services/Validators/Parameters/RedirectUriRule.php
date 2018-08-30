<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 5:03 PM
 */

namespace Oauth\Services\Validators\Parameters;

use Respect\Validation\Validator;

class RedirectUriRule extends ParameterRule
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::url()->length(7, 4000)->notBlank();
    }
}