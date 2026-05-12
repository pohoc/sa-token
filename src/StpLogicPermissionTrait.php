<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;
use SaToken\Exception\NotRoleException;
use SaToken\Util\SaFoxUtil;

trait StpLogicPermissionTrait
{
    public function checkPermission(string $permission): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        if (!SaFoxUtil::inArray($permissionList, $permission)) {
            throw new NotPermissionException((string) $permission);
        }
    }

    /**
     * @param array<string> $permissions
     */
    public function checkPermissionOr(array $permissions): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        foreach ($permissions as $permission) {
            if (SaFoxUtil::inArray($permissionList, $permission)) {
                return;
            }
        }
        throw new NotPermissionException(implode(',', $permissions));
    }

    /**
     * @param array<string> $permissions
     */
    public function checkPermissionAnd(array $permissions): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        foreach ($permissions as $permission) {
            if (!SaFoxUtil::inArray($permissionList, $permission)) {
                throw new NotPermissionException($permission);
            }
        }
    }

    public function hasPermission(string $permission): bool
    {
        try {
            $this->checkPermission($permission);
            return true;
        } catch (NotPermissionException $e) {
            return false;
        } catch (NotLoginException $e) { // @phpstan-ignore catch.neverThrown
            return false;
        }
    }

    public function checkRole(string $role): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        if (!SaFoxUtil::inArray($roleList, $role)) {
            throw new NotRoleException($role);
        }
    }

    /**
     * @param array<string> $roles
     */
    public function checkRoleOr(array $roles): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        foreach ($roles as $role) {
            if (SaFoxUtil::inArray($roleList, $role)) {
                return;
            }
        }
        throw new NotRoleException(implode(',', $roles));
    }

    /**
     * @param array<string> $roles
     */
    public function checkRoleAnd(array $roles): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        foreach ($roles as $role) {
            if (!SaFoxUtil::inArray($roleList, $role)) {
                throw new NotRoleException($role);
            }
        }
    }

    public function hasRole(string $role): bool
    {
        try {
            $this->checkRole($role);
            return true;
        } catch (NotRoleException $e) {
            return false;
        } catch (NotLoginException $e) { // @phpstan-ignore catch.neverThrown
            return false;
        }
    }

    /**
     * @return array<string>
     */
    public function getPermissionList(mixed $loginId): array
    {
        $action = SaToken::getAction();
        if ($action === null) {
            return [];
        }
        return $action->getPermissionList($loginId, $this->loginType);
    }

    /**
     * @return array<string>
     */
    public function getRoleList(mixed $loginId): array
    {
        $action = SaToken::getAction();
        if ($action === null) {
            return [];
        }
        return $action->getRoleList($loginId, $this->loginType);
    }
}
