<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 2:53 PM
 */

namespace Oauth\Services\Validators\RequestValidators;

class GenericRequestValidator extends RequestValidator
{
    /**
     * RequestValidator constructor.
     * @param array[string]ParameterRule $parametersValidator
     */
    public function __construct(array $parametersValidator)
    {
        $this->parametersValidator = $parametersValidator;
    }
}