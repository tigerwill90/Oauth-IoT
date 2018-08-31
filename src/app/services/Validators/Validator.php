<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:44 PM
 */

namespace Oauth\Services\Validators;

use Oauth\Services\Validators\Parameters\ParameterRule;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class Validator
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
    protected $missingParameterErrors = [];

    /** @var string[] */
    protected $validatorParameterErrors = [];

    public function __construct(){}

    /**
     * Add a new ParameterRule
     * @param string $field
     * @param ParameterRule $parameterRule
     * @return Validator
     */
    public function add(string $field, ParameterRule $parameterRule) : Validator
    {
        $this->parametersValidator[$field] = $parameterRule;
        return $this;
    }

    public function checkParametersExist(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody() ?? [];
        $parameters = [];
        foreach ($this->parametersValidator as $key => $paramValidator) {
            $attribute = $request->getAttribute($key);
            if ($paramValidator instanceof ParameterRule) {
                if (!array_key_exists($key, $args) && null === $attribute && $paramValidator->isRequired()) {
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

    public function validateParameters(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody() ?? [];
        foreach ($this->parametersValidator as $key => $paramValidator) {
            $attribute = $request->getAttribute($key);
            if ($paramValidator instanceof ParameterRule) {
                try {
                    if (array_key_exists($key, $args)) {
                        $paramValidator->getValidator()->setName($key)->assert($args[$key]);
                    } else if (null !== $attribute) {
                        $paramValidator->getValidator()->setName($key)->assert($attribute);
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