<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:57 PM
 */

namespace Oauth\Services\ClientService;

use Respect\Validation\Validator;

class ClientValidator
{

    /**
     * ClientValidator constructor.
     * @param array[string]array[string]Validator $mandatoryRequestParameter
     */
    public function __construct(array $parameters)
    {
    }

    /**
     * @param array[string]string $registerRequestParameter
     * @return bool
     */
    public function validate(array $registerRequestParameter) : bool
    {
        return false;
    }

    private function checkMandatoryParameters() : bool
    {
        return false;
    }
}