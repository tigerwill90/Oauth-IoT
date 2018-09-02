<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 4:59 PM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class ClientTypeRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::in(['confidential', 'public'])->notBlank();
    }
}
