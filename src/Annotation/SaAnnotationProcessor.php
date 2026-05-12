<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use ReflectionClass;
use SaToken\SaToken;
use SaToken\Security\SaSensitiveVerify;

class SaAnnotationProcessor
{
    public static function process(string $class, string $method): void
    {
        if (!class_exists($class)) {
            return;
        }
        $reflectionClass = new ReflectionClass($class);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $classAttributes = $reflectionClass->getAttributes();
        $methodAttributes = $reflectionMethod->getAttributes();

        foreach ($methodAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        foreach ($classAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        $allAttributes = array_merge($classAttributes, $methodAttributes);

        foreach ($allAttributes as $attr) {
            $instance = $attr->newInstance();
            $loginType = method_exists($instance, 'getLoginType') ? $instance->getLoginType() : 'login';
            if (!is_string($loginType)) {
                $loginType = 'login';
            }
            $stpLogic = SaToken::getStpLogic($loginType);

            if ($instance instanceof SaCheckLogin) {
                $stpLogic->checkLogin();
            } elseif ($instance instanceof SaCheckPermission) {
                $permissions = explode(',', $instance->getValue());
                $permissions = array_map('trim', $permissions);
                if ($instance->getMode() === 'AND') {
                    $stpLogic->checkPermissionAnd($permissions);
                } else {
                    $stpLogic->checkPermissionOr($permissions);
                }
            } elseif ($instance instanceof SaCheckRole) {
                $roles = explode(',', $instance->getValue());
                $roles = array_map('trim', $roles);
                if ($instance->getMode() === 'AND') {
                    $stpLogic->checkRoleAnd($roles);
                } else {
                    $stpLogic->checkRoleOr($roles);
                }
            } elseif ($instance instanceof SaCheckSafe) {
                $service = $instance->getService();
                $loginId = $stpLogic->getLoginId();

                if ($service === 'otp' || str_starts_with($service, 'verify:')) {
                    $stpLogic->checkSafe($service);
                } elseif ($loginId !== null) {
                    if (!SaSensitiveVerify::isVerified($service, is_scalar($loginId) ? (string) $loginId : '', $loginType)) {
                        $stpLogic->checkSafe($service);
                    }
                } else {
                    $stpLogic->checkSafe($service);
                }
            } elseif ($instance instanceof SaCheckDisable) {
                $loginId = $stpLogic->getLoginId();
                if ($loginId !== null) {
                    $stpLogic->checkDisable($loginId, $instance->getService());
                }
            }
        }
    }

    public static function processCallable(callable $callable): void
    {
    }

    /**
     * @return array<object>
     */
    public static function getMethodAttributes(string $class, string $method): array
    {
        if (!class_exists($class)) {
            return [];
        }
        $reflectionClass = new ReflectionClass($class);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $result = [];
        $classAttrs = $reflectionClass->getAttributes();
        $methodAttrs = $reflectionMethod->getAttributes();

        foreach (array_merge($classAttrs, $methodAttrs) as $attr) {
            if (str_starts_with($attr->getName(), 'SaToken\\Annotation\\')) {
                $result[] = $attr->newInstance();
            }
        }

        return $result;
    }
}
