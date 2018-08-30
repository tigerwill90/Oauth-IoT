<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:04 AM
 */

namespace Oauth\Services\Validator\Parameters;

use Respect\Validation\Validator;

class ClientName extends ParameterRule
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
            return Validator::alnum()->length(3, 80)->notBlank();
    }
}