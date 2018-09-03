<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:42 PM
 */

namespace Oauth\Services\Validators\Rules;


use Respect\Validation\Validator;

class AudienceRule extends RuleValidator
{

    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::alnum('_')->noWhitespace()->notBlank();
    }
}