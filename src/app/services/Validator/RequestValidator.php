<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:44 PM
 */

namespace Oauth\Services\Validators;

use Oauth\Services\Validator\Parameters\ClientNameRule;
use Oauth\Services\Validator\Parameters\ParameterRule;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class RequestValidator
{
    /**
     * <code>
     * $parametersValidator = [
     *      'client_id' => new ClientNameRule(true),
     *      'parameter' => ParameterRule
     * ]
     * @var array[string]ParameterRule
     */
    private $parametersValidator;

    /** @var string[] */
    private $missingParameterErrors = [];

    /** @var string[] */
    private $validatorParameterErrors = [];

    /**
     * RequestValidator constructor.
     * @param array[string]ParameterRule $parametersValidator
     */
    public function __construct(array $parametersValidator = null)
    {
        if ($parametersValidator === null) {
            $this->parametersValidator = [
                'client_name' => new ClientNameRule(true)
            ];
        } else {
            $this->parametersValidator = $parametersValidator;
        }
    }

    public function checkParametersExist(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody();
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if (!array_key_exists($key, $args)) {
                $this->missingParameterErrors[] = $key . 'parameter is missing';
            }
        }
        return empty($this->missingParameterErrors);
    }

    public function validateParameters(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody();
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof ParameterRule) {
                try {
                    return $paramValidator->getValidator()->assert($args[$key]);
                } catch (NestedValidationException $e) {
                    $this->validatorParameterErrors = $e->getMessages();
                    return false;
                }
            } else {
                throw new \InvalidArgumentException('All parameter validator muse be an instance of ParameterRule');
            }
        }
        return false;
    }

    public function getErrors() : array
    {
        return array_merge($this->missingParameterErrors, $this->validatorParameterErrors);
    }
}