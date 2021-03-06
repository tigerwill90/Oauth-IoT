<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 31.08.2018
 * Time: 18:39
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class ClientIdentificationRule extends RuleValidator
{

    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::alnum()->notBlank()->length(1, 15)->noWhitespace();
    }
}
