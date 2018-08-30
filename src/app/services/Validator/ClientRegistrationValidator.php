<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:44 PM
 */

namespace Oauth\Services\Validators;

use Oauth\Services\Validator\Parameters\ClientName;
use Oauth\Services\Validator\Parameters\ParameterRule;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class ClientRegistrationValidator extends RequestValidator
{
    /**
     * <code>
     * $parametersValidator = [
     *      'client_id' => new ClientName(true),
     *      'parameter' => ParameterRule
     * ]
     * @var array[string]ParameterRule
     */
    private $parametersValidator;

    /**
     * ClientRegistrationValidator constructor.
     * @param array[string]ParameterRule $parametersValidator
     */
    public function __construct(array $parametersValidator = null)
    {
        if ($parametersValidator === null) {
            $this->parametersValidator = [
                'client_name' => new ClientName(true)
            ];
        } else {
            $this->parametersValidator = $parametersValidator;
        }
    }

    // TODO implements
    public function checkParametersExist(ServerRequestInterface $request): bool
    {
        return false;
    }

    // TODO maybe just needs args
    public function validateParameter(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody();
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof ParameterRule) {
                try {
                    return $paramValidator->getValidator()->assert($args[$key]);
                } catch (NestedValidationException $e) {

                    return false;
                }
            } else {
                throw new \InvalidArgumentException('All parameter validator muse be an instance of ParameterRule');
            }
        }
        return false;
    }
}