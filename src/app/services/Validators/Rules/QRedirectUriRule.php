<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 3:37 PM
 */

namespace Oauth\Services\Validators\Rules;


use Respect\Validation\Validator;

class QRedirectUriRule extends RuleValidator
{

    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::url();
    }
}