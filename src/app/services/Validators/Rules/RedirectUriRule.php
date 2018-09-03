<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 5:03 PM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class RedirectUriRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::arrayType()->each(Validator::url()->length(7, 4000)->noWhitespace())->notEmpty();
    }
}
