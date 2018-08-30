<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:44 PM
 */

namespace Oauth\Services\Validators\RequestValidators;

use Oauth\Services\Validators\Parameters\ParameterRule;
use Respect\Validation\Exceptions\NestedValidationException;

abstract class RequestValidator
{
    /**
     * <code>
     * $parametersValidator = [
     *      'client_id' => new ClientNameRule(true),
     *      'parameter' => ParameterRule
     * ]
     * @var array[string]ParameterRule
     */
    protected $parametersValidator;

    /** @var string[] */
    private $missingParameterErrors = [];

    /** @var string[] */
    private $validatorParameterErrors = [];

    public function checkParametersExist(array $args): bool
    {
        $parameters = [];
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof ParameterRule) {
                if (!array_key_exists($key, $args) && $paramValidator->isRequired()) {
                    $parameters[] = $key . ' parameter is required';
                }
            } else {
                throw new \InvalidArgumentException('Value of ' . $key . ' must be a child instance of ParameterRule');
            }
        }
        if (!empty($parameters)) {
            $this->missingParameterErrors['parameters'] = $parameters;
        }
        return empty($this->missingParameterErrors);
    }

    public function validateParameters(array $args): bool
    {
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof ParameterRule) {
                try {
                    if (array_key_exists($key, $args)) {
                        $paramValidator->getValidator()->setName($key)->assert($args[$key]);
                    }
                } catch (NestedValidationException $e) {
                    $this->validatorParameterErrors[$key] = $e->getMessages();
                }
            } else {
                throw new \InvalidArgumentException('Key : ' . $key . ' => ' . $paramValidator . ' must be an instance of ParameterRule');
            }
        }
        return empty($this->validatorParameterError);
    }

    public function getErrorsMessages() : array
    {
        return array_merge($this->missingParameterErrors, $this->validatorParameterErrors);
    }
}